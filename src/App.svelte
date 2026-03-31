<script>
    import { onMount, tick } from 'svelte';
    import protobuf from 'protobufjs';
    import QRCode from 'qrcode';
    import { Html5Qrcode } from 'html5-qrcode';

    // --- SVELTE STATE MANAGEMENT (Der UX-Flow) ---
    // Mögliche Schritte: 'OFFER_ZEIGEN', 'SCANNEN', 'ANSWER_ZEIGEN', 'CHAT'
    let currentStep = 'OFFER_ZEIGEN';
    let qrDataUrl = '';
    let chatMessages = [];
    let messageInput = '';
    let scanner = null;

    // --- 1. PROTOBUF DEFINITION ---
    const SIGNAL_PROTO = `
    syntax = "proto3";
    package webrtc;
    message Candidate {
      uint32 port = 1;
      uint32 priority = 2;
      enum CandType { HOST = 0; SRFLX = 1; RELAY = 2; }
      CandType typ = 3;
      oneof ip_data {
        bytes ipv4 = 4;
        bytes ipv6 = 5;
        string domain = 6;
      }
    }
    message SignalMessage {
      uint32 version = 1;
      uint64 sessionId = 2;
      enum MessageType { OFFER = 0; ANSWER = 1; }
      MessageType type = 3;
      string ufrag = 4;
      string pwd = 5;
      bytes fingerprint = 6;
      repeated Candidate candidates = 7;
    }`;

    const root = protobuf.parse(SIGNAL_PROTO).root;
    const SignalMessage = root.lookupType("webrtc.SignalMessage");

    // --- 2. WEBRTC SETUP ---
    let pc;
    let dataChannel;

    const config = {
        iceServers: [
            { urls: 'stun:stun.l.google.com:19302' }
        ]
    };

    function initPeerConnection() {
        pc = new RTCPeerConnection(config);

        pc.onicegatheringstatechange = () => {
            if (pc.iceGatheringState === 'complete') {
                generateQrCode(pc.localDescription);
            }
        };

        pc.ondatachannel = (event) => {
            setupDataChannel(event.channel);
        };
    }

    function setupDataChannel(channel) {
        dataChannel = channel;
        dataChannel.onopen = () => {
            // MAGIE: Sobald die Netzwerkverbindung steht, schaltet Svelte
            // automatisch bei beiden Geräten alle QR-Codes weg und den Chat ein!
            currentStep = 'CHAT';
            chatMessages = [...chatMessages, { sender: 'System', text: 'Verbunden! Ihr seid live.', color: 'green' }];
        };
        dataChannel.onmessage = (event) => {
            chatMessages = [...chatMessages, { sender: 'Peer', text: event.data, color: 'blue' }];
        };
    }

    async function createOffer() {
        initPeerConnection();
        const channel = pc.createDataChannel("chat");
        setupDataChannel(channel);

        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
    }

    async function createAnswer() {
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        // Da wir das Answer generiert haben, zeigen wir es jetzt an
        currentStep = 'ANSWER_ZEIGEN';
    }

    // --- 3. HILFSFUNKTIONEN FÜR IPv6 & BIGINT ---
    function parseIPv6(ip) {
        const parts = ip.split('::');
        let blocks = [];
        if (parts.length === 2) {
            const left = parts[0] ? parts[0].split(':') : [];
            const right = parts[1] ? parts[1].split(':') : [];
            const missing = 8 - (left.length + right.length);
            const zeros = Array(missing).fill('0');
            blocks = [...left, ...zeros, ...right];
        } else {
            blocks = ip.split(':');
        }
        const bytes = new Uint8Array(16);
        for (let i = 0; i < 8; i++) {
            const val = parseInt(blocks[i] || '0', 16);
            bytes[i * 2] = val >> 8;
            bytes[i * 2 + 1] = val & 0xff;
        }
        return bytes;
    }

    function stringifyIPv6(bytes) {
        let blocks = [];
        for (let i = 0; i < 8; i++) {
            const val = (bytes[i * 2] << 8) | bytes[i * 2 + 1];
            blocks.push(val.toString(16));
        }
        return blocks.join(':');
    }

    function encodeToNumeric(buffer) {
        let num = 1n;
        for (let i = 0; i < buffer.length; i++) {
            num = (num << 8n) | BigInt(buffer[i]);
        }
        return num.toString(10);
    }

    function decodeFromNumeric(str) {
        let num = BigInt(str);
        let bytes = [];
        while (num > 1n) {
            bytes.unshift(Number(num & 255n));
            num = num >> 8n;
        }
        return new Uint8Array(bytes);
    }

    // --- 4. SDP KOMPRIMIERUNG & PROTOBUF ---
    function parseSdpToObject(sdp, typeStr) {
        const obj = {
            version: 1,
            sessionId: Date.now() % 100000000,
            type: typeStr === 'offer' ? 0 : 1,
            candidates: []
        };

        const lines = sdp.split('\r\n');
        for (const line of lines) {
            if (line.startsWith('a=ice-ufrag:')) obj.ufrag = line.substring(12);
            if (line.startsWith('a=ice-pwd:')) obj.pwd = line.substring(10);
            if (line.startsWith('a=fingerprint:sha-256 ')) {
                const hexArr = line.substring(22).split(':');
                obj.fingerprint = new Uint8Array(hexArr.map(h => parseInt(h, 16)));
            }
            if (line.startsWith('a=candidate:')) {
                const parts = line.split(' ');
                const ipString = parts[4];

                if (parts[2] === 'UDP' && parts[6] === 'typ') {
                    const typStr = parts[7];
                    let typVal = 0;
                    if (typStr === 'srflx') typVal = 1;
                    else if (typStr === 'relay') typVal = 2;

                    const isIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(ipString);
                    const isIPv6 = ipString.includes(':');
                    const isMDNS = ipString.endsWith('.local');

                    if (isIPv4 && (typStr === 'host' || typStr === 'srflx' || typStr === 'relay')) {
                        obj.candidates.push({ port: parseInt(parts[5]), priority: parseInt(parts[3]), typ: typVal, ipv4: new Uint8Array(ipString.split('.').map(Number)) });
                    } else if (isIPv6 && (typStr === 'host' || typStr === 'srflx' || typStr === 'relay')) {
                        obj.candidates.push({ port: parseInt(parts[5]), priority: parseInt(parts[3]), typ: typVal, ipv6: parseIPv6(ipString) });
                    } else if (isMDNS && typStr === 'host') {
                        obj.candidates.push({ port: parseInt(parts[5]), priority: parseInt(parts[3]), typ: typVal, domain: ipString });
                    }
                }
            }
        }

        // Kandidaten-Diät (Maximal 2)
        let filtered = [];
        let hasPublic = false;
        let hasLocal = false;

        for (let c of obj.candidates) {
            if ((c.typ === 1 || c.typ === 2) && !hasPublic) { filtered.push(c); hasPublic = true; }
            else if (c.typ === 0 && !hasLocal) { filtered.push(c); hasLocal = true; }
            if (filtered.length >= 2) break;
        }
        if (filtered.length === 0 && obj.candidates.length > 0) filtered.push(obj.candidates[0]);

        obj.candidates = filtered;
        return obj;
    }

    function reconstructSdp(obj) {
        const fphex = Array.from(obj.fingerprint || []).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
        const setupType = obj.type === 0 ? 'actpass' : 'active';

        let sdp = [
            `v=0`, `o=- ${obj.sessionId} 2 IN IP4 127.0.0.1`, `s=-`, `t=0 0`,
            `a=msid-semantic: WMS`, `m=application 9 UDP/DTLS/SCTP webrtc-datachannel`,
            `c=IN IP4 0.0.0.0`, `a=mid:0`, `a=sctp-port:5000`, `a=setup:${setupType}`,
            `a=fingerprint:sha-256 ${fphex}`, `a=ice-ufrag:${obj.ufrag}`, `a=ice-pwd:${obj.pwd}`,
        ].join('\r\n') + '\r\n';

        if (obj.candidates) {
            obj.candidates.forEach(c => {
                const candType = c.typ === 1 ? 'srflx' : c.typ === 2 ? 'relay' : 'host';
                let ipAddress = "";
                if (c.ipv4 && c.ipv4.length === 4) ipAddress = Array.from(c.ipv4).join('.');
                else if (c.ipv6 && c.ipv6.length === 16) ipAddress = stringifyIPv6(c.ipv6);
                else if (c.domain) ipAddress = c.domain;

                if (ipAddress !== "") {
                    let extra = candType !== 'host' ? " raddr 0.0.0.0 rport 0" : "";
                    sdp += `a=candidate:1 1 UDP ${c.priority} ${ipAddress} ${c.port} typ ${candType}${extra}\r\n`;
                }
            });
        }
        return sdp;
    }

    async function generateQrCode(desc) {
        const obj = parseSdpToObject(desc.sdp, desc.type);
        const message = SignalMessage.create(obj);
        const buffer = SignalMessage.encode(message).finish();

        // ULTIMATIVER HACK: Wir erzwingen Numeric Mode!
        const numericStr = encodeToNumeric(buffer);

        try {
            // Das neue qrcode Paket erlaubt es uns, den Daten-Modus explizit vorzugeben
            qrDataUrl = await QRCode.toDataURL([{ data: numericStr, mode: 'numeric' }], {
                errorCorrectionLevel: 'L',
                margin: 2,
                width: 350
            });
        } catch (err) {
            console.error("QR Code Fehler", err);
        }
    }

    // --- 5. SCANNER & VERARBEITUNG ---
    async function startScanner() {
        currentStep = 'SCANNEN';
        await tick(); // Svelte Zeit geben, das <div id="reader"> in den DOM zu rendern

        scanner = new Html5Qrcode("reader");
        scanner.start(
            { facingMode: "environment" },
            { fps: 10, qrbox: { width: 250, height: 250 } },
            async (scannedText) => {
                await stopScanner();
                await processScannedSignal(scannedText);
            },
            (errorMessage) => { /* Ignorieren, da er bei jedem Frame ohne QR feuert */ }
        );
    }

    async function stopScanner() {
        if (scanner) {
            try {
                await scanner.stop();
                scanner.clear();
            } catch (e) {}
            scanner = null;
        }
    }

    async function abortScanning() {
        await stopScanner();
        // Fallback zur vorherigen Anzeige basierend darauf, wo wir waren
        currentStep = (pc && pc.localDescription && pc.localDescription.type === 'answer') ? 'ANSWER_ZEIGEN' : 'OFFER_ZEIGEN';
    }

    async function processScannedSignal(scannedText) {
        try {
            const bytes = decodeFromNumeric(scannedText);
            const obj = SignalMessage.decode(bytes);
            const sdpString = reconstructSdp(obj);
            const sdpType = obj.type === 0 ? 'offer' : 'answer';

            if (!pc) initPeerConnection();

            await pc.setRemoteDescription(new RTCSessionDescription({ type: sdpType, sdp: sdpString }));

            if (sdpType === 'offer') {
                // Wir haben ein Offer gescannt -> Wir generieren das Answer
                await createAnswer();
                // Das generieren löst automatisch aus, dass wir zum ANSWER_ZEIGEN Schritt springen.
            } else {
                // Wir haben ein Answer gescannt -> Wir warten auf die P2P Verbindung!
                chatMessages = [...chatMessages, { sender: 'System', text: 'Answer verarbeitet. Verbinde...', color: 'orange' }];
            }

        } catch (e) {
            console.error("Fehler beim Verarbeiten:", e);
            alert("Ungültiger QR-Code gescannt.");
            abortScanning();
        }
    }

    // --- 6. CHAT UI ---
    function sendMessage() {
        if (messageInput.trim() && dataChannel && dataChannel.readyState === 'open') {
            dataChannel.send(messageInput);
            chatMessages = [...chatMessages, { sender: 'Du', text: messageInput, color: 'black' }];
            messageInput = '';
        }
    }

    // Lifecycle Hook: Wird aufgerufen, wenn die Seite das erste Mal geladen ist
    onMount(() => {
        createOffer(); // Startet den Prozess direkt ohne Klick!
    });

</script>

<main class="container">
    <h1>P2P Chat</h1>

    {#if currentStep === 'OFFER_ZEIGEN'}
        <div class="card">
            <p><strong>Schritt 1:</strong> Lass diesen Code scannen oder scanne das andere Gerät.</p>
            {#if qrDataUrl}
                <img src={qrDataUrl} alt="Offer QR Code" class="qr-image" />
            {:else}
                <p>Generiere Code...</p>
            {/if}
            <button class="btn primary" on:click={startScanner}>Kamera starten & scannen</button>
        </div>

    {:else if currentStep === 'SCANNEN'}
        <div class="card scanner-card">
            <p>Richte die Kamera auf den QR-Code des anderen Geräts.</p>
            <div id="reader" style="width: 100%; border-radius: 8px; overflow: hidden;"></div>
            <button class="btn secondary" on:click={abortScanning}>Abbrechen</button>
        </div>

    {:else if currentStep === 'ANSWER_ZEIGEN'}
        <div class="card">
            <p><strong>Fast fertig!</strong><br>Lass diesen Code jetzt vom ersten Gerät scannen, um die Verbindung herzustellen.</p>
            {#if qrDataUrl}
                <img src={qrDataUrl} alt="Answer QR Code" class="qr-image" />
            {/if}
        </div>

    {:else if currentStep === 'CHAT'}
        <div class="card chat-card">
            <div class="chat-box">
                {#each chatMessages as msg}
                    <div style="color: {msg.color}; margin-bottom: 8px;">
                        <strong>{msg.sender}:</strong> {msg.text}
                    </div>
                {/each}
            </div>
            <div class="chat-input-row">
                <input type="text" bind:value={messageInput} placeholder="Nachricht..." on:keydown={(e) => e.key === 'Enter' && sendMessage()} autofocus />
                <button class="btn primary" on:click={sendMessage}>Senden</button>
            </div>
        </div>
    {/if}
</main>

<style>
    /* Globales, modernes Styling */
    :global(body) {
        font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background-color: #f4f4f9;
        margin: 0;
        padding: 0;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
    }

    .container {
        width: 100%;
        max-width: 400px;
        padding: 20px;
        box-sizing: border-box;
    }

    h1 {
        text-align: center;
        color: #333;
        margin-bottom: 20px;
    }

    .card {
        background: white;
        padding: 24px;
        border-radius: 12px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        text-align: center;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 16px;
    }

    .qr-image {
        max-width: 100%;
        height: auto;
        border-radius: 8px;
        border: 4px solid #fff;
        box-shadow: 0 2px 8px rgba(0,0,0,0.05);
    }

    .btn {
        width: 100%;
        padding: 12px 20px;
        border: none;
        border-radius: 8px;
        font-size: 16px;
        font-weight: 600;
        cursor: pointer;
        transition: background-color 0.2s;
    }

    .btn.primary { background-color: #007bff; color: white; }
    .btn.primary:hover { background-color: #0056b3; }
    .btn.secondary { background-color: #e0e0e0; color: #333; }
    .btn.secondary:hover { background-color: #c8c8c8; }

    .chat-card {
        align-items: stretch;
    }

    .chat-box {
        height: 300px;
        overflow-y: auto;
        border: 1px solid #ddd;
        border-radius: 8px;
        padding: 12px;
        background: #fafafa;
        text-align: left;
    }

    .chat-input-row {
        display: flex;
        gap: 8px;
        margin-top: 12px;
    }

    .chat-input-row input {
        flex: 1;
        padding: 12px;
        border: 1px solid #ddd;
        border-radius: 8px;
        font-size: 16px;
    }
</style>