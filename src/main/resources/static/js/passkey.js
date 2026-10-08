/*
 * Lado do navegador das cerimônias WebAuthn.
 *
 * Fluxo (registro e autenticação são simétricos):
 *   1. POST /api/passkeys/.../options -> servidor devolve as opções em JSON (binários em Base64URL)
 *   2. Converte o JSON em objetos com ArrayBuffer e chama navigator.credentials.create()/get()
 *   3. Serializa a credencial de volta para JSON (Base64URL) e envia para /api/passkeys/.../verify
 */
(() => {
    'use strict';

    // ---------------------------------------------------------------- log visível na página
    const logList = document.getElementById('client-log');

    function log(message, level = 'info', data) {
        const colors = {info: 'text-slate-200', ok: 'text-emerald-400', warn: 'text-amber-400', error: 'text-red-400'};
        const item = document.createElement('li');
        item.className = colors[level] || colors.info;
        item.textContent = `${new Date().toLocaleTimeString('pt-BR')}  ${message}`;
        if (data !== undefined) {
            const pre = document.createElement('pre');
            pre.className = 'ml-4 whitespace-pre-wrap text-slate-400';
            pre.textContent = JSON.stringify(data, null, 2);
            item.appendChild(pre);
        }
        logList.appendChild(item);
        logList.scrollTop = logList.scrollHeight;
        (level === 'error' ? console.error : console.debug)('[passkey]', message, data ?? '');
    }

    document.getElementById('clear-log').addEventListener('click', () => logList.replaceChildren());

    // ---------------------------------------------------------------- Base64URL <-> ArrayBuffer
    function bufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (const b of bytes) binary += String.fromCharCode(b);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function base64urlToBuffer(value) {
        const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }

    const toDescriptor = (d) => ({...d, id: base64urlToBuffer(d.id)});

    // Navegadores recentes têm parse*OptionsFromJSON nativo; os demais usam a conversão manual.
    function toCreationOptions(json) {
        if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function') {
            return PublicKeyCredential.parseCreationOptionsFromJSON(json);
        }
        return {
            ...json,
            challenge: base64urlToBuffer(json.challenge),
            user: {...json.user, id: base64urlToBuffer(json.user.id)},
            excludeCredentials: (json.excludeCredentials || []).map(toDescriptor),
        };
    }

    function toRequestOptions(json) {
        if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function') {
            return PublicKeyCredential.parseRequestOptionsFromJSON(json);
        }
        return {
            ...json,
            challenge: base64urlToBuffer(json.challenge),
            allowCredentials: (json.allowCredentials || []).map(toDescriptor),
        };
    }

    // Serializa a PublicKeyCredential no formato RegistrationResponseJSON/AuthenticationResponseJSON.
    function credentialToJSON(credential) {
        if (typeof credential.toJSON === 'function') {
            try {
                return credential.toJSON();
            } catch (e) {
                log(`toJSON() nativo falhou (${e.message}); usando serialização manual`, 'warn');
            }
        }
        const r = credential.response;
        const response = {clientDataJSON: bufferToBase64url(r.clientDataJSON)};
        if (r.attestationObject) { // registro
            response.attestationObject = bufferToBase64url(r.attestationObject);
            response.transports = typeof r.getTransports === 'function' ? r.getTransports() : [];
        } else { // autenticação
            response.authenticatorData = bufferToBase64url(r.authenticatorData);
            response.signature = bufferToBase64url(r.signature);
            if (r.userHandle) response.userHandle = bufferToBase64url(r.userHandle);
        }
        return {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
            clientExtensionResults: credential.getClientExtensionResults(),
            response,
        };
    }

    // ---------------------------------------------------------------- HTTP
    async function postJSON(url, body) {
        const response = await fetch(url, {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
            body: JSON.stringify(body ?? {}),
        });
        const requestId = response.headers.get('X-Request-Id');
        const payload = await response.json().catch(() => ({}));
        log(`${url} -> HTTP ${response.status} (X-Request-Id: ${requestId ?? '-'})`, response.ok ? 'info' : 'warn');
        if (!response.ok) {
            throw new Error(payload.detail || payload.title || `HTTP ${response.status}`);
        }
        return payload;
    }

    // ---------------------------------------------------------------- feedback visual
    function showResult(elementId, ok, message) {
        const el = document.getElementById(elementId);
        el.className = `mt-3 rounded p-3 text-sm ${ok ? 'bg-emerald-50 text-emerald-800' : 'bg-red-50 text-red-800'}`;
        el.textContent = message;
    }

    // Erros do navegador (DOMException) têm nomes padronizados; traduzimos os mais comuns.
    function describeError(error) {
        switch (error.name) {
            case 'NotAllowedError':
                return 'Operação cancelada pelo usuário ou tempo esgotado.';
            case 'InvalidStateError':
                return 'Este autenticador já possui uma passkey para este usuário (excludeCredentials).';
            case 'SecurityError':
                return 'Origem ou RP ID inválidos para esta página (verifique passkey.rp-id e a URL).';
            case 'NotSupportedError':
                return 'Nenhum autenticador suporta os parâmetros pedidos.';
            case 'AbortError':
                return 'Operação abortada.';
            default:
                return error.message || String(error);
        }
    }

    function withBusy(form, fn) {
        return async (event) => {
            event.preventDefault();
            const button = form.querySelector('button[type=submit]');
            button.disabled = true;
            try {
                await fn(new FormData(form));
            } finally {
                button.disabled = false;
            }
        };
    }

    // ---------------------------------------------------------------- registro
    const registerForm = document.getElementById('register-form');
    registerForm.addEventListener('submit', withBusy(registerForm, async (form) => {
        try {
            log('[Registro 1/3] Pedindo opções ao servidor');
            const optionsJSON = await postJSON('/api/passkeys/registration/options', Object.fromEntries(form));
            log('[Registro 1/3] Opções recebidas (PublicKeyCredentialCreationOptionsJSON)', 'info', optionsJSON);

            log('[Registro 2/3] Chamando navigator.credentials.create() — interaja com o autenticador');
            const credential = await navigator.credentials.create({publicKey: toCreationOptions(optionsJSON)});
            const credentialJSON = credentialToJSON(credential);
            log(`[Registro 2/3] Credencial criada: id=${credential.id}, attachment=${credential.authenticatorAttachment ?? '-'}`,
                'info', {transports: credentialJSON.response.transports, clientExtensionResults: credentialJSON.clientExtensionResults});

            log('[Registro 3/3] Enviando resposta para verificação');
            const result = await postJSON('/api/passkeys/registration/verify', credentialJSON);
            log(`[Registro 3/3] ${result.message}`, 'ok', result);
            showResult('register-result', true, `${result.message} (${result.kind})`);
            htmx.trigger(document.body, 'credentialsChanged');
        } catch (error) {
            log(`[Registro] Falhou: ${error.name}: ${error.message}`, 'error');
            showResult('register-result', false, describeError(error));
        }
    }));

    // ---------------------------------------------------------------- autenticação
    const loginForm = document.getElementById('login-form');
    loginForm.addEventListener('submit', withBusy(loginForm, async (form) => {
        try {
            log('[Autenticação 1/3] Pedindo opções ao servidor');
            const optionsJSON = await postJSON('/api/passkeys/authentication/options', Object.fromEntries(form));
            log('[Autenticação 1/3] Opções recebidas (PublicKeyCredentialRequestOptionsJSON)', 'info', optionsJSON);

            log('[Autenticação 2/3] Chamando navigator.credentials.get() — interaja com o autenticador');
            const credential = await navigator.credentials.get({publicKey: toRequestOptions(optionsJSON)});
            log(`[Autenticação 2/3] Asserção assinada pela credencial ${credential.id}`);

            log('[Autenticação 3/3] Enviando asserção para verificação');
            const result = await postJSON('/api/passkeys/authentication/verify', credentialToJSON(credential));
            log(`[Autenticação 3/3] ${result.message}`, 'ok', result);
            showResult('login-result', true, `${result.message} signCount=${result.signCount}, UV=${result.userVerified}`);
            htmx.trigger(document.body, 'credentialsChanged');
            htmx.trigger(document.body, 'sessionChanged');
        } catch (error) {
            log(`[Autenticação] Falhou: ${error.name}: ${error.message}`, 'error');
            showResult('login-result', false, describeError(error));
        }
    }));

    // ---------------------------------------------------------------- detecção de suporte
    async function detectSupport() {
        const el = document.getElementById('support');
        if (!window.PublicKeyCredential) {
            el.className = 'rounded-lg bg-red-50 p-4 text-sm text-red-800';
            el.textContent = 'Este navegador não suporta WebAuthn. Use uma versão recente de Chrome, Edge, Safari ou Firefox.';
            log('WebAuthn indisponível neste navegador', 'error');
            return;
        }
        const check = async (fn) => {
            try {
                return typeof fn === 'function' ? await fn() : 'n/d';
            } catch {
                return 'n/d';
            }
        };
        const platform = await check(PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable);
        const conditional = await check(PublicKeyCredential.isConditionalMediationAvailable);
        const items = [
            ['Contexto seguro (HTTPS ou localhost)', window.isSecureContext],
            ['Autenticador de plataforma com verificação (Touch ID, Windows Hello…)', platform],
            ['Preenchimento automático de passkeys (conditional mediation)', conditional],
            ['PublicKeyCredential.parseCreationOptionsFromJSON', typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function'],
        ];
        el.innerHTML = '<strong class="mb-1 block">Suporte deste navegador</strong>';
        const ul = document.createElement('ul');
        ul.className = 'grid gap-1 sm:grid-cols-2';
        for (const [label, value] of items) {
            const li = document.createElement('li');
            li.textContent = `${value === true ? '✅' : value === false ? '❌' : '➖'} ${label}`;
            ul.appendChild(li);
        }
        el.appendChild(ul);
        log('Suporte detectado', 'info', Object.fromEntries(items));
    }

    detectSupport();
})();
