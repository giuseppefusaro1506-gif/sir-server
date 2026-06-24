# S.I.R. — Sistema Informativo Riservato
## Istruzioni di installazione e avvio

### Requisiti
- Node.js 18+ (https://nodejs.org)
- Connessione internet per le tile OpenStreetMap

---

### 1. Installazione dipendenze

```bash
cd sir-server
npm install
```

---

### 2. Configurazione (server.js — sezione CONFIG)

Apri `server.js` e modifica il blocco `CONFIG`:

```js
const CONFIG = {
  PORT:           3000,          // porta del server
  ADMIN_PASSWORD: 'direttore984', // password pannello organizzatori

  LEVEL_CODES: {
    'SDC2026':      2,   // codice per sbloccare L2
    'SANTADRIANO':  3,   // codice per L3
    'STRIGARI':     4,   // codice per L4
    'BELLUSCI':     5,   // codice per L5
    'DIRETTORE984': 6,   // codice per L6
  },

  SQUADRE: [
    { nome: 'Squadra Alfa',  password: 'alfa2026'  },
    { nome: 'Squadra Beta',  password: 'beta2026'  },
    // aggiungi o modifica...
  ],
};
```

> **Attenzione:** i codici di livello non sono mai esposti al client.
> Il client manda il codice al server che lo valida. 
> Aprire il sorgente del client non rivela nulla.

---

### 3. Avvio

```bash
node server.js
```

Il server stampa le credenziali e si mette in ascolto.

---

### 4. Accesso

| URL | Cosa |
|-----|------|
| `http://IP:3000/` | Client squadre |
| `http://IP:3000/admin.html` | Pannello organizzatori |

Per renderlo accessibile dalla rete locale, usa l'IP della macchina
(es. `http://192.168.1.10:3000`).

Per renderlo accessibile da internet usa **ngrok**:
```bash
npx ngrok http 3000
```
ngrok fornisce un URL pubblico tipo `https://xxxx.ngrok.io`.

---

### 5. Pannello organizzatori

Password: quella impostata in `ADMIN_PASSWORD`.

Funzioni disponibili:
- **Monitoraggio live**: chi è connesso, a che livello, ultima attività
- **Set livello manuale**: forza una squadra a un livello specifico
- **Reset squadra**: riporta una squadra a L1
- **Broadcast**: invia un messaggio popup a tutte le squadre connesse
- **Log storico**: tutti gli accessi, i codici inseriti (giusti e sbagliati), i livelli sbloccati

---

### 6. Struttura file

```
sir-server/
├── server.js          ← server principale (modifica CONFIG qui)
├── package.json
├── db/
│   └── sir.db         ← database SQLite (creato automaticamente)
└── public/
    ├── index.html     ← client squadre
    └── admin.html     ← pannello organizzatori
```

---

### 7. Reset completo tra una sessione e l'altra

Cancella `db/sir.db` — il server ricrea tutto al riavvio.

