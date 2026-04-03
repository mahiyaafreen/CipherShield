let mediaRecorder;
let recordedChunks = [];

// -------------------------------
// Start Recording
// -------------------------------
document.getElementById("startRec").onclick = function () {
    navigator.mediaDevices.getUserMedia({ audio: true }).then(stream => {
        mediaRecorder = new MediaRecorder(stream);
        recordedChunks = [];

        mediaRecorder.ondataavailable = e => recordedChunks.push(e.data);

        mediaRecorder.onstop = () => {
            document.getElementById("recStatus").textContent = "Recording completed.";
        };

        mediaRecorder.start();
        document.getElementById("recStatus").textContent = "Recording...";
        document.getElementById("stopRec").disabled = false;
    });
};


// -------------------------------
// Stop Recording
// -------------------------------
document.getElementById("stopRec").onclick = function () {
    mediaRecorder.stop();
    this.disabled = true;
    document.getElementById("encryptAudio").disabled = false;
};


// -------------------------------
// AES Encryption (Browser-Side)
// -------------------------------
async function encryptBinaryAES(data, keyHex) {

    const key = await crypto.subtle.importKey(
        "raw",
        hexToBytes(keyHex),
        { name: "AES-GCM" },
        false,
        ["encrypt"]
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        data
    );

    return {
        iv: iv,
        ct: new Uint8Array(encrypted)
    };
}


// Convert Hex → Uint8
function hexToBytes(hex) {
    const arr = [];
    for (let i = 0; i < hex.length; i += 2) {
        arr.push(parseInt(hex.substr(i, 2), 16));
    }
    return new Uint8Array(arr);
}


// -------------------------------
// Encrypt Audio Button
// -------------------------------
document.getElementById("encryptAudio").onclick = async function () {

    const blob = new Blob(recordedChunks, { type: "audio/webm" });
    const arrayBuffer = await blob.arrayBuffer();
    const uint8 = new Uint8Array(arrayBuffer);

    // Generate AES key (256-bit)
    const keyBytes = crypto.getRandomValues(new Uint8Array(32));
    const keyHex = Array.from(keyBytes).map(b => b.toString(16).padStart(2, "0")).join("");

    // Encrypt
    const encrypted = await encryptBinaryAES(uint8, keyHex);

    // Pack encrypted audio into a Blob
    const encBlob = new Blob([encrypted.ct], { type: "application/octet-stream" });
    const fileInput = document.getElementById("encAudioFile");

    // Set encrypted blob as file input
    const file = new File([encBlob], "encrypted_audio.bin");
    const dataTransfer = new DataTransfer();
    dataTransfer.items.add(file);
    fileInput.files = dataTransfer.files;

    // Show AES key & upload form
    document.getElementById("audioKey").value = keyHex;
    document.getElementById("encResult").style.display = "block";

    document.getElementById("recStatus").textContent = "Audio encrypted.";
};
