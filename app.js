const MAGIC = new TextEncoder().encode('STEGOSAFE');
const VERSION = 1;
const HEADER_SIZE = 14;
const SALT_SIZE = 16;
const IV_SIZE = 12;
const PBKDF2_ITERATIONS = 65536;
const MAX_PIXELS = 40_000_000;
const encoder = new TextEncoder();

const elements = {
  hideTab: document.querySelector('#hide-tab'),
  extractTab: document.querySelector('#extract-tab'),
  hidePanel: document.querySelector('#hide-panel'),
  extractPanel: document.querySelector('#extract-panel'),
  hideFile: document.querySelector('#hide-file'),
  extractFile: document.querySelector('#extract-file'),
  hideDrop: document.querySelector('#hide-drop'),
  extractDrop: document.querySelector('#extract-drop'),
  hidePreview: document.querySelector('#hide-preview'),
  extractPreview: document.querySelector('#extract-preview'),
  hideFileLabel: document.querySelector('#hide-file-label'),
  extractFileLabel: document.querySelector('#extract-file-label'),
  hideImageMeta: document.querySelector('#hide-image-meta'),
  extractImageMeta: document.querySelector('#extract-image-meta'),
  hideCapacity: document.querySelector('#hide-capacity'),
  capacityValue: document.querySelector('#capacity-value'),
  message: document.querySelector('#secret-message'),
  messageSize: document.querySelector('#message-size'),
  hidePassword: document.querySelector('#hide-password'),
  confirmPassword: document.querySelector('#confirm-password'),
  hideButton: document.querySelector('#hide-button'),
  extractPassword: document.querySelector('#extract-password'),
  extractButton: document.querySelector('#extract-button'),
  status: document.querySelector('#status-message'),
  resultBox: document.querySelector('#result-box'),
  resultMessage: document.querySelector('#extracted-message'),
  copyButton: document.querySelector('#copy-button')
};

let hideImage = null;
let extractImage = null;
let hidePreviewUrl = null;
let extractPreviewUrl = null;
let capacityBytes = 0;

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function setStatus(message, kind = 'error') {
  elements.status.textContent = message;
  elements.status.classList.toggle('success', kind === 'success');
  elements.status.hidden = false;
  elements.status.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function clearStatus() {
  elements.status.hidden = true;
  elements.status.textContent = '';
}

function toggleMode(mode) {
  const isHide = mode === 'hide';
  elements.hideTab.classList.toggle('active', isHide);
  elements.extractTab.classList.toggle('active', !isHide);
  elements.hideTab.setAttribute('aria-selected', String(isHide));
  elements.extractTab.setAttribute('aria-selected', String(!isHide));
  elements.hidePanel.hidden = !isHide;
  elements.extractPanel.hidden = isHide;
  clearStatus();
}

function getImageData(image) {
  const canvas = document.createElement('canvas');
  canvas.width = image.width;
  canvas.height = image.height;
  const context = canvas.getContext('2d', { willReadFrequently: true });
  context.drawImage(image, 0, 0);
  return { canvas, context, imageData: context.getImageData(0, 0, canvas.width, canvas.height) };
}

async function loadImage(file, preview, label, meta, mode) {
  if (!file || !file.type.startsWith('image/')) throw new Error('Choose a supported image file.');
  const objectUrl = URL.createObjectURL(file);
  try {
    const image = new Image();
    image.decoding = 'async';
    image.src = objectUrl;
    await image.decode();
    if (!image.width || !image.height) throw new Error('This image could not be decoded.');
    if (image.width * image.height > MAX_PIXELS) throw new Error('This image is over the 40-megapixel processing limit. Choose a smaller image.');

    preview.src = objectUrl;
    preview.hidden = false;
    preview.parentElement.querySelector('.preview-empty').hidden = true;
    label.textContent = file.name;
    meta.textContent = `${image.width} × ${image.height} · ${formatBytes(file.size)}`;

    if (mode === 'hide') {
      if (hidePreviewUrl) URL.revokeObjectURL(hidePreviewUrl);
      hidePreviewUrl = objectUrl;
      hideImage = image;
      capacityBytes = Math.max(0, Math.floor(image.width * image.height * 3 / 8) - 70);
      elements.capacityValue.textContent = formatBytes(capacityBytes);
      elements.hideCapacity.hidden = false;
      updateHideButton();
    } else {
      if (extractPreviewUrl) URL.revokeObjectURL(extractPreviewUrl);
      extractPreviewUrl = objectUrl;
      extractImage = image;
      elements.resultBox.hidden = true;
      elements.extractButton.disabled = false;
    }
    clearStatus();
  } catch (error) {
    URL.revokeObjectURL(objectUrl);
    throw error;
  }
}

function updateHideButton() {
  const messageSize = encoder.encode(elements.message.value).length;
  elements.messageSize.textContent = formatBytes(messageSize);
  const valid = hideImage && messageSize > 0 && messageSize <= capacityBytes
    && elements.hidePassword.value.length >= 6
    && elements.hidePassword.value === elements.confirmPassword.value;
  elements.hideButton.disabled = !valid;
  if (hideImage && messageSize > capacityBytes) {
    elements.messageSize.textContent = `${formatBytes(messageSize)} · too large`;
  }
}

function writeUint32(view, offset, value) {
  view.setUint32(offset, value, false);
}

function buildPayload(salt, iv, ciphertext) {
  const bodyLength = 4 + salt.length + 4 + iv.length + 4 + ciphertext.length;
  const payload = new Uint8Array(HEADER_SIZE + bodyLength);
  payload.set(MAGIC, 0);
  payload[9] = VERSION;
  const view = new DataView(payload.buffer);
  writeUint32(view, 10, bodyLength);
  let offset = HEADER_SIZE;
  writeUint32(view, offset, salt.length); offset += 4;
  payload.set(salt, offset); offset += salt.length;
  writeUint32(view, offset, iv.length); offset += 4;
  payload.set(iv, offset); offset += iv.length;
  writeUint32(view, offset, ciphertext.length); offset += 4;
  payload.set(ciphertext, offset);
  return payload;
}

async function deriveKey(password, salt, usages) {
  const passwordBytes = encoder.encode(password);
  const material = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
  passwordBytes.fill(0);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    usages
  );
}

function embedPayload(imageData, payload) {
  const { data } = imageData;
  const capacity = Math.floor(data.length / 4 * 3 / 8);
  if (payload.length > capacity) throw new Error(`This message needs ${formatBytes(payload.length)} but the image can hold ${formatBytes(capacity)}.`);
  let byteIndex = 0;
  let bitIndex = 0;
  for (let pixel = 0; pixel < data.length / 4 && byteIndex < payload.length; pixel++) {
    const base = pixel * 4;
    for (let channel = 0; channel < 3 && byteIndex < payload.length; channel++) {
      const bit = (payload[byteIndex] >> (7 - bitIndex)) & 1;
      data[base + channel] = (data[base + channel] & 0xfe) | bit;
      bitIndex++;
      if (bitIndex === 8) { bitIndex = 0; byteIndex++; }
    }
  }
}

function extractBytes(imageData, length) {
  const { data } = imageData;
  const capacity = Math.floor(data.length / 4 * 3 / 8);
  if (length > capacity) throw new Error('The image does not have enough pixel data for this payload.');
  const output = new Uint8Array(length);
  let byteIndex = 0;
  let currentByte = 0;
  let bitCount = 0;
  for (let pixel = 0; pixel < data.length / 4 && byteIndex < length; pixel++) {
    const base = pixel * 4;
    for (let channel = 0; channel < 3 && byteIndex < length; channel++) {
      currentByte = (currentByte << 1) | (data[base + channel] & 1);
      if (++bitCount === 8) {
        output[byteIndex++] = currentByte;
        currentByte = 0;
        bitCount = 0;
      }
    }
  }
  if (byteIndex !== length) throw new Error('Image ended before the complete payload could be read.');
  return output;
}

function parsePayload(payload) {
  if (payload.length < HEADER_SIZE || !MAGIC.every((byte, index) => payload[index] === byte)) {
    throw new Error('No StegoSafe message was found in this image.');
  }
  if (payload[9] !== VERSION) throw new Error(`Unsupported StegoSafe payload version: ${payload[9]}.`);
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const bodyLength = view.getUint32(10, false);
  if (bodyLength < 56 || bodyLength + HEADER_SIZE > payload.length) throw new Error('The embedded payload is incomplete or invalid.');

  let offset = HEADER_SIZE;
  const readPart = (minLength, maxLength, label) => {
    if (offset + 4 > payload.length) throw new Error(`The ${label} length is missing.`);
    const length = view.getUint32(offset, false); offset += 4;
    if (length < minLength || length > maxLength || offset + length > payload.length) throw new Error(`The ${label} data is invalid.`);
    const part = payload.slice(offset, offset + length);
    offset += length;
    return part;
  };
  const salt = readPart(8, 64, 'salt');
  const iv = readPart(12, 16, 'IV');
  const ciphertext = readPart(17, bodyLength, 'ciphertext');
  if (offset !== HEADER_SIZE + bodyLength) throw new Error('The payload contains inconsistent length values.');
  return { salt, iv, ciphertext };
}

async function encryptMessage() {
  if (!window.isSecureContext || !crypto.subtle) throw new Error('Secure browser cryptography is unavailable. Open this site on localhost or HTTPS.');
  const message = elements.message.value;
  const password = elements.hidePassword.value;
  if (!hideImage) throw new Error('Choose a carrier image first.');
  if (!message.trim()) throw new Error('Write a message before creating the image.');
  if (password.length < 6) throw new Error('Use a password with at least 6 characters.');
  if (password !== elements.confirmPassword.value) throw new Error('The passwords do not match.');

  const plaintext = encoder.encode(message);
  const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
  const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
  const key = await deriveKey(password, salt, ['encrypt']);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, plaintext));
  plaintext.fill(0);
  const payload = buildPayload(salt, iv, encrypted);
  const { canvas, context, imageData } = getImageData(hideImage);
  embedPayload(imageData, payload);
  context.putImageData(imageData, 0, 0);

  const png = await new Promise((resolve, reject) => canvas.toBlob(blob => blob ? resolve(blob) : reject(new Error('Could not encode the finished image as PNG.')), 'image/png'));
  const url = URL.createObjectURL(png);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'stegosafe-image.png';
  link.click();
  URL.revokeObjectURL(url);
  elements.hidePassword.value = '';
  elements.confirmPassword.value = '';
  setStatus(`Your encrypted PNG is ready (${formatBytes(png.size)}). Keep the original file and share the password separately.`, 'success');
}

function readPayload(imageData) {
  const capacity = Math.floor(imageData.data.length / 4 * 3 / 8);
  if (capacity < HEADER_SIZE) throw new Error('This image is too small to contain a StegoSafe message.');
  const prefix = extractBytes(imageData, HEADER_SIZE);
  if (!MAGIC.every((byte, index) => prefix[index] === byte)) throw new Error('No StegoSafe message was found in this image.');
  if (prefix[9] !== VERSION) throw new Error(`Unsupported StegoSafe payload version: ${prefix[9]}.`);
  const bodyLength = new DataView(prefix.buffer).getUint32(10, false);
  if (bodyLength < 56 || HEADER_SIZE + bodyLength > capacity) throw new Error('The payload size is invalid or exceeds this image.');
  return parsePayload(extractBytes(imageData, HEADER_SIZE + bodyLength));
}

async function decryptMessage() {
  if (!window.isSecureContext || !crypto.subtle) throw new Error('Secure browser cryptography is unavailable. Open this site on localhost or HTTPS.');
  if (!extractImage) throw new Error('Choose a StegoSafe image first.');
  const password = elements.extractPassword.value;
  if (!password) throw new Error('Enter the password for this message.');
  const { imageData } = getImageData(extractImage);
  const { salt, iv, ciphertext } = readPayload(imageData);
  const key = await deriveKey(password, salt, ['decrypt']);
  let plaintext;
  try {
    plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ciphertext));
  } catch {
    throw new Error('Incorrect password or corrupted image.');
  }
  try {
    elements.resultMessage.textContent = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
  } catch {
    throw new Error('The decrypted message is not valid UTF-8 text.');
  } finally {
    plaintext.fill(0);
  }
  elements.resultBox.hidden = false;
  elements.extractPassword.value = '';
  setStatus('Message authenticated and recovered.', 'success');
}

function bindFileInput(input, preview, label, meta, mode, dropZone) {
  const accept = file => loadImage(file, preview, label, meta, mode).catch(error => setStatus(error.message));
  input.addEventListener('change', () => accept(input.files[0]));
  for (const eventName of ['dragenter', 'dragover']) {
    dropZone.addEventListener(eventName, event => { event.preventDefault(); dropZone.classList.add('dragging'); });
  }
  for (const eventName of ['dragleave', 'drop']) {
    dropZone.addEventListener(eventName, event => { event.preventDefault(); dropZone.classList.remove('dragging'); });
  }
  dropZone.addEventListener('drop', event => accept(event.dataTransfer.files[0]));
}

elements.hideTab.addEventListener('click', () => toggleMode('hide'));
elements.extractTab.addEventListener('click', () => toggleMode('extract'));
bindFileInput(elements.hideFile, elements.hidePreview, elements.hideFileLabel, elements.hideImageMeta, 'hide', elements.hideDrop);
bindFileInput(elements.extractFile, elements.extractPreview, elements.extractFileLabel, elements.extractImageMeta, 'extract', elements.extractDrop);
elements.message.addEventListener('input', updateHideButton);
elements.hidePassword.addEventListener('input', updateHideButton);
elements.confirmPassword.addEventListener('input', updateHideButton);
elements.hideButton.addEventListener('click', async () => {
  elements.hideButton.disabled = true;
  elements.hideButton.querySelector('span').textContent = 'Encrypting…';
  clearStatus();
  try { await encryptMessage(); }
  catch (error) { setStatus(error.message); }
  finally { elements.hideButton.querySelector('span').textContent = 'Encrypt & create PNG'; updateHideButton(); }
});
elements.extractButton.addEventListener('click', async () => {
  elements.extractButton.disabled = true;
  elements.extractButton.querySelector('span').textContent = 'Scanning…';
  clearStatus();
  try { await decryptMessage(); }
  catch (error) { setStatus(error.message); }
  finally { elements.extractButton.querySelector('span').textContent = 'Scan & decrypt'; elements.extractButton.disabled = !extractImage; }
});
elements.copyButton.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(elements.resultMessage.textContent);
    elements.copyButton.textContent = 'Copied';
    window.setTimeout(() => { elements.copyButton.textContent = 'Copy'; }, 1400);
  } catch { setStatus('Clipboard access is unavailable in this browser.'); }
});

if (!window.isSecureContext || !crypto.subtle) {
  setStatus('For secure cryptography, open this site from localhost or an HTTPS address.');
}