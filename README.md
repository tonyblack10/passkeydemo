# Passkey Demo

Aplicação de demonstração de **passkeys (WebAuthn/FIDO2)** com **Spring Web** e a biblioteca [webauthn4j](https://webauthn4j.github.io/webauthn4j/en/), **sem Spring Security**. Cada etapa do protocolo fica explícita no código e nos logs, para fins didáticos.

Funcionalidades:

- **Registro** de passkeys: um ou mais autenticadores por usuário.
- **Autenticação (validação)** com ou sem username (credencial descobrível).
- **Listagem e remoção** das passkeys registradas, com detalhes: algoritmo, AAGUID, transportes, flags BE/BS/UV e signCount.
- **Escolha do tipo de autenticador**: qualquer, este dispositivo (Touch ID, Windows Hello), chave de segurança ou celular via QR code.
- **Logs detalhados** com `requestId` para correlacionar navegador e servidor.

> 📘 A explicação completa da tecnologia (conceitos, fluxos, vantagens, desvantagens e **todas as opções de configuração**) está em **[PASSKEYS.md](PASSKEYS.md)**.

## Tecnologias

| Camada | Tecnologia |
|---|---|
| Backend | Java 25, Spring Boot 4.1 (Web MVC), Bean Validation |
| WebAuthn | webauthn4j-core 0.31.11 |
| Persistência | Em memória (`ConcurrentHashMap`) |
| Interface | Thymeleaf, htmx 2, Tailwind CSS (CDN) |
| Testes | JUnit 5, MockMvc, webauthn4j-test (autenticador emulado) |

## Pré-requisitos

- **JDK 25** ou superior
- Navegador com suporte a passkeys: Chrome/Edge, Safari ou Firefox recentes
- Um autenticador: Touch ID/Face ID, Windows Hello, Android, chave de segurança FIDO2 ou o autenticador virtual do Chrome DevTools

O Maven não precisa estar instalado: o projeto inclui o Maven Wrapper (`./mvnw`).

## Como executar

```bash
./mvnw spring-boot:run
```

Acesse **http://localhost:8080**.

> ⚠️ Use `localhost`, e não `127.0.0.1`: a origem da página precisa coincidir com `passkey.origins` e `passkey.rp-id`.

### Roteiro rápido

1. **Registrar**: informe um username (ex.: `maria`) e clique em **Criar passkey**.
2. **Entrar**: informe o username, ou deixe em branco para escolher entre as passkeys salvas, e clique em **Entrar com passkey**.
3. **Listar e remover**: acompanhe as passkeys na tabela; remova e tente entrar de novo para ver a falha.
4. Acompanhe o **Log do navegador** na página e o console da aplicação.

Sem Touch ID ou chave de segurança? No Chrome, abra **DevTools → ⋮ → More tools → WebAuthn** e ative o *virtual authenticator environment*.

## Testes

```bash
./mvnw test
```

Os testes de integração (`PasskeyFlowTests`) usam o autenticador emulado do `webauthn4j-test` para executar os fluxos completos de registro e autenticação, sem navegador. Também verificam a rejeição de replay, de origem inválida (phishing), de verificação sem challenge e de dados inválidos.

## Configuração

As principais opções ficam em `src/main/resources/application.properties`:

```properties
# Domínio ao qual as passkeys ficam vinculadas
passkey.rp-id=localhost
# Nome exibido pelo autenticador
passkey.rp-name=Passkey Demo
# Origens aceitas (separe várias com vírgula)
passkey.origins=http://localhost:8080
# Espera do navegador e validade do challenge
passkey.timeout=120s
# required | preferred | discouraged
passkey.user-verification=preferred
# required | preferred | discouraged
passkey.resident-key=required
# none | indirect | direct | enterprise
passkey.attestation=none
# vazio (qualquer) | platform | cross-platform
passkey.authenticator-attachment=
# ES256, EdDSA, RS256
passkey.algorithms=-7,-8,-257
```

Cada opção está explicada em detalhes na [seção 9 do PASSKEYS.md](PASSKEYS.md#9-referência-de-configuração).

Para publicar em outro domínio (HTTPS obrigatório fora de `localhost`):

```properties
passkey.rp-id=demo.exemplo.com.br
passkey.origins=https://demo.exemplo.com.br
```

## API

| Método | Caminho | Descrição |
|---|---|---|
| `POST` | `/api/passkeys/registration/options` | Registro, passo 1: gera o challenge e as opções |
| `POST` | `/api/passkeys/registration/verify` | Registro, passo 2: valida e salva a passkey |
| `POST` | `/api/passkeys/authentication/options` | Login, passo 1: gera o challenge e as opções |
| `POST` | `/api/passkeys/authentication/verify` | Login, passo 2: valida a assinatura |
| `GET` | `/fragments/credentials` | Fragmento htmx com a lista de passkeys |
| `GET` | `/fragments/session` | Fragmento htmx com o status da sessão |
| `DELETE` | `/credentials/{id}` | Remove uma passkey |
| `POST` | `/logout` | Encerra a sessão |

Erros da API seguem o formato **Problem Details** (RFC 9457).

## Estrutura do projeto

```
src/main/java/io/github/tonyblack10/passkeydemo
├── config       # WebAuthnProperties (passkey.*) e beans do webauthn4j
├── model        # UserAccount, StoredCredential
├── repository   # repositórios em memória
├── service      # RegistrationService, AuthenticationService, ChallengeStore...
├── dto          # JSON trocado com o navegador
└── web          # controllers, tratamento de erros, filtro de log
src/main/resources
├── templates    # index.html e fragmentos htmx
└── static/js    # passkey.js (chamadas à API WebAuthn do navegador)
```

## Limitações

Esta é uma aplicação **didática**, não pronta para produção:

- os dados ficam **em memória** e se perdem ao reiniciar;
- não há **autorização** nem **proteção CSRF**: qualquer visitante pode listar e remover passkeys;
- o challenge fica na `HttpSession` local, então funciona com **uma única instância**;
- Tailwind e htmx são carregados via **CDN**.

Veja as [boas práticas de segurança](PASSKEYS.md#11-boas-práticas-de-segurança) para os ajustes necessários em produção.
