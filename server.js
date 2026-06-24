/**
 * K.A.R.I. — Kernel Archivistico Ricerche Investigative
 * Server Node.js + WebSocket + SQLite
 * ============================================================
 * SICUREZZA: i dati classificati sono serviti dal server
 * solo quando la squadra ha la clearance corretta.
 * Il client non contiene mai codici, trame o segreti.
 * ============================================================
 */

const express      = require('express');
const http         = require('http');
const WebSocket    = require('ws');
const session      = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt       = require('bcryptjs');
const { v4: uuid } = require('uuid');
const initSqlJs    = require('sql.js');
const path         = require('path');
const fs           = require('fs');

/* ============================================================
   CONFIGURAZIONE — unico posto dove modificare segreti
   ============================================================ */
const CONFIG = {
  PORT:           3000,
  SESSION_SECRET: 'kari-sdc-2026-segreto',
  DB_PATH:        path.join(__dirname, 'db', 'kari.db'),
  ADMIN_PASSWORD: 'direttore984',

  // Codici trovati sul campo → clearance sbloccata
  // Non compaiono mai nel codice del client
  CODICI_CLEARANCE: {
    'SDC2026':      2,
    'SANTADRIANO':  3,
    'STRIGARI':     4,
    'BELLUSCI':     5,
    'DIRETTORE984': 6,
  },

  // Squadre: aggiungile/modificale qui, poi cancella kari.db e riavvia
  SQUADRE: [
    { nome: 'Squadra Alfa',  password: 'alfa2026'  },
    { nome: 'Squadra Beta',  password: 'beta2026'  },
    { nome: 'Squadra Gamma', password: 'gamma2026' },
    { nome: 'Squadra Delta', password: 'delta2026' },
    { nome: 'Squadra Zeta',  password: 'zeta2026'  },
    { nome: 'Squadra Omega', password: 'omega2026' },
  ],
};

/* ============================================================
   DATABASE INVESTIGATIVO — tutto il contenuto classificato
   vive qui sul server, mai nel browser
   ============================================================ */
const ARCHIVIO = {

  // ── PERSONE ──────────────────────────────────────────────
  // clearance: minima clearance per vedere i campi sensibili
  // campi_pubblici: visibili da CL1 (niente di rivelatore)
  // campi_cl3: dettaglio professionale + nota investigativa
  // campi_cl5: identità riservata + nota completa
  persone: [
    {
      id: 'P001',
      // CL1-4: identità oscurata
      cognome_pubblico:    '[OMISSIS]',
      nome_pubblico:       '[OMISSIS]',
      cognome_riservato:   'Bellusci',
      nome_riservato:      'Vincenzo',
      nato:                '1951-03-14',
      luogo_nascita:       'San Demetrio Corone',
      residenza:           'San Demetrio Corone',
      professione:         'Insegnante di lettere (in pensione)',
      flag:                ['chiave'],
      alias:               'Il Professore',
      nota_cl1:            'Soggetto scomparso — Caso 27/2026. Identità classificata CL.5.',
      nota_cl3:            'Ultimo avvistamento: Via Domenico Mauro, ore 21:40. Portava borsa di tela. Direzione centro storico.',
      nota_cl5:            'IDENTITÀ: Vincenzo Bellusci, 14/03/1951. Scomparso nella notte 12-13 luglio 2026 mentre si recava a restituire l\'Anello Strigari. Non è mai arrivato. La borsa nell\'auto era VUOTA: aveva l\'Anello con sé.',
    },
    {
      id: 'P002',
      cognome_pubblico:    'Strigari',
      nome_pubblico:       'Costantino',
      cognome_riservato:   null,
      nome_riservato:      null,
      nato:                '1941-08-15',
      luogo_nascita:       'San Demetrio Corone',
      residenza:           'San Demetrio Corone',
      professione:         'Proprietario terriero',
      flag:                ['chiave'],
      alias:               'Don Tino',
      nota_cl1:            '',
      nota_cl3:            'Destinatario dell\'Anello. Ultima comunicazione con il Professore: 10/07 ore 18:32. "Finalmente. Sapevo che sarebbe tornato."',
      nota_cl5:            'Non sapeva della scomparsa fino al 14/07. Intercettazione T005 rivela: sapeva qualcosa di più. Tenere sotto osservazione.',
    },
    {
      id: 'P003',
      cognome_pubblico:    'Pangallo',
      nome_pubblico:       'Maria Grazia',
      cognome_riservato:   null,
      nome_riservato:      null,
      nato:                '1968-04-22',
      luogo_nascita:       'Corigliano Calabro',
      residenza:           'San Demetrio Corone',
      professione:         'Commerciante — alimentari',
      flag:                ['testimone'],
      alias:               '',
      nota_cl1:            'Testimone',
      nota_cl3:            'Ha visto il Professore la sera del 12/07 verso le 21:30 in Via D. Mauro. Camminava spedito verso il centro. Si è mostrata nervosa durante l\'interrogatorio del 14/07.',
      nota_cl5:            'Il marito Bruno Pangallo (P017) non ha saputo spiegare la presenza del suo furgone a Brunetti quella notte. La moglie copre? PISTA APERTA.',
    },
    {
      id: 'P004',
      cognome_pubblico:    'Scorpino',
      nome_pubblico:       'Raffaele',
      cognome_riservato:   null,
      nome_riservato:      null,
      nato:                '1961-11-03',
      luogo_nascita:       'Acri',
      residenza:           'San Demetrio Corone',
      professione:         'Notaio',
      flag:                ['sospetto'],
      alias:               "L'Avvocatino",
      nota_cl1:            '',
      nota_cl3:            'Due telefonate al Professore nei 10 giorni precedenti. Dichiarazione: pratica notarile eredità padre.',
      nota_cl5:            'PISTA RIAPERTA — intercettazione T005: "Non coinvolgermi più in questa storia, Costantino." Sapeva qualcosa di più del testamento. Richiedere tabulati completi.',
    },
    {
      id: 'P005',
      cognome_pubblico:    'Stranges',
      nome_pubblico:       'Rocco',
      cognome_riservato:   null,
      nome_riservato:      null,
      nato:                '1972-09-14',
      luogo_nascita:       'San Demetrio Corone',
      residenza:           'San Demetrio Corone',
      professione:         'Agricoltore',
      flag:                ['testimone'],
      alias:               '',
      nota_cl1:            'Testimone oculare principale',
      nota_cl3:            'Ultima persona a vedere il Professore. Chiamata ricevuta ore 20:55: "Vado a portare la cosa." Lo conosce da trent\'anni. Credibile.',
      nota_cl5:            'Nessun elemento sospetto. Testimonianza confermata da Pangallo Maria Grazia indipendentemente.',
    },
    {
      id: 'P006',
      cognome_pubblico:    'Veltri',
      nome_pubblico:       'Carmelo',
      cognome_riservato:   null,
      nome_riservato:      null,
      nato:                '1958-06-30',
      luogo_nascita:       'San Demetrio Corone',
      residenza:           'San Demetrio Corone',
      professione:         'Ex sindaco — imprenditore agricolo',
      flag:                ['sospetto'],
      alias:               'Il Sindaco',
      nota_cl1:            '',
      nota_cl3:            'Auto (V007) avvistata zona Trappeto il 12/07 ore 19:00. Chiamata a Strigari 4 giorni prima (T007, 8 minuti). Non ha fornito spiegazioni soddisfacenti.',
      nota_cl5:            'PISTA APERTA PRIORITÀ ALTA. La nota D005 del Professore riporta: "Cosa sa Veltri???" Sapeva dell\'Anello? Da quando? Richiedere verifica patrimoni e rapporti con Strigari negli ultimi 10 anni.',
    },
    {
      id: 'P007',
      cognome_pubblico:    'Mazzuca',
      nome_pubblico:       'Saverio',
      cognome_riservato:   null, nome_riservato: null,
      nato: '1980-02-17', luogo_nascita: 'Rossano', residenza: 'San Demetrio Corone',
      professione: 'Muratore',
      flag: [], alias: '',
      nota_cl1: '', nota_cl3: '', nota_cl5: '',
    },
    {
      id: 'P008',
      cognome_pubblico:    'Canino',
      nome_pubblico:       'Lucia',
      cognome_riservato:   null, nome_riservato: null,
      nato: '1975-11-28', luogo_nascita: 'San Demetrio Corone', residenza: 'San Demetrio Corone',
      professione: 'Insegnante elementari',
      flag: [], alias: '',
      nota_cl1: '', nota_cl3: '', nota_cl5: '',
    },
    {
      id: 'P009',
      cognome_pubblico:    'Perri',
      nome_pubblico:       'Antonio',
      cognome_riservato:   null, nome_riservato: null,
      nato: '1963-07-04', luogo_nascita: 'Lungro', residenza: 'San Demetrio Corone',
      professione: 'Falegname',
      flag: [], alias: 'Tonino',
      nota_cl1: '', nota_cl3: 'Bottega sul Corso. Ha notato movimenti insoliti in Piazza Crispi la sera del 12/07 ma non ha formalmente testimoniato.', nota_cl5: '',
    },
    {
      id: 'P010',
      cognome_pubblico:    'Frasca',
      nome_pubblico:       'Giuseppe',
      cognome_riservato:   null, nome_riservato: null,
      nato: '1950-03-20', luogo_nascita: 'San Demetrio Corone', residenza: 'Macchia Albanese',
      professione: 'Pensionato',
      flag: [], alias: 'Peppino',
      nota_cl1: '', nota_cl3: '', nota_cl5: '',
    },
    {
      id: 'P011',
      cognome_pubblico:    'Cristofaro',
      nome_pubblico:       'Angela',
      cognome_riservato:   null, nome_riservato: null,
      nato: '1988-09-11', luogo_nascita: 'Cosenza', residenza: 'San Demetrio Corone',
      professione: 'Infermiera — presidio medico locale',
      flag: [], alias: '',
      nota_cl1: '', nota_cl3: 'Ha dichiarato di aver visto una persona "confusa e affannata" vicino al Collegio verso le 22:00 del 12/07. Non ha riconosciuto il volto.', nota_cl5: '',
    },
    {
      id: 'P012',
      cognome_pubblico:    'Torchia',
      nome_pubblico:       'Domenico',
      cognome_riservato:   null, nome_riservato: null,
      nato: '1945-12-25', luogo_nascita: 'San Demetrio Corone', residenza: 'San Demetrio Corone',
      professione: 'Pensionato — ex maresciallo dei Carabinieri',
      flag: [], alias: 'Il Maresciallo',
      nota_cl1: '', nota_cl3: 'Conosce da decenni sia il Professore che Veltri. Potrebbe sapere qualcosa sui loro rapporti passati.', nota_cl5: '',
    },
    {
      id: 'P013',
      cognome_pubblico:    'Brutto',
      nome_pubblico:       'Francesco',
      cognome_riservato:   null, nome_riservato: null,
      nato: '1992-05-08', luogo_nascita: 'Acri', residenza: 'San Demetrio Corone',
      professione: 'Tecnico informatico — riparazioni hardware',
      flag: [], alias: 'Ciccio',
      nota_cl1: '', nota_cl3: 'Ha riparato un vecchio hard disk del Professore nel maggio 2026. Ha dichiarato che era "pieno di documenti storici, mappe, fotografie di oggetti antichi". Non ricorda altro.', nota_cl5: '',
    },
    {
      id: 'P014',
      cognome_pubblico:    'Plastino',
      nome_pubblico:       'Rosa',
      cognome_riservato:   null, nome_riservato: null,
      nato: '1970-08-16', luogo_nascita: 'San Demetrio Corone', residenza: 'San Demetrio Corone',
      professione: 'Casalinga',
      flag: [], alias: '',
      nota_cl1: '', nota_cl3: '', nota_cl5: '',
    },
    {
      id: 'P015',
      cognome_pubblico:    'Scarpino',
      nome_pubblico:       'Vittorio',
      cognome_riservato:   null, nome_riservato: null,
      nato: '1955-01-30', luogo_nascita: 'Corigliano Calabro', residenza: 'San Demetrio Corone',
      professione: 'Commercialista',
      flag: [], alias: '',
      nota_cl1: '', nota_cl3: 'Gestisce i conti della famiglia Strigari da vent\'anni. Ha rifiutato di commentare.', nota_cl5: '',
    },
    {
      id: 'P016',
      cognome_pubblico:    'Strigari',
      nome_pubblico:       'Rosaria',
      cognome_riservato:   null, nome_riservato: null,
      nato: '1945-03-12', luogo_nascita: 'San Demetrio Corone', residenza: 'San Demetrio Corone',
      professione: 'Pensionata',
      flag: [], alias: '',
      nota_cl1: '', nota_cl3: 'Sorella di Costantino Strigari (P002). Ha dichiarato di non sapere nulla dell\'Anello.', nota_cl5: '',
    },
    {
      id: 'P017',
      cognome_pubblico:    'Pangallo',
      nome_pubblico:       'Bruno',
      cognome_riservato:   null, nome_riservato: null,
      nato: '1966-07-19', luogo_nascita: 'San Demetrio Corone', residenza: 'Sofferetti',
      professione: 'Agricoltore — terreni zona Sofferetti e Brunetti',
      flag: ['sospetto'], alias: '',
      nota_cl1: '', nota_cl3: 'Marito di P003. Furgone (V004) segnalato a Brunetti mezzanotte del 12/07. "Controllavo le pompe dell\'irrigazione." Non verificabile.', nota_cl5: '',
    },
    {
      id: 'P018',
      cognome_pubblico:    'Carnevale',
      nome_pubblico:       'Concetta',
      cognome_riservato:   null, nome_riservato: null,
      nato: '1978-10-03', luogo_nascita: 'Cosenza', residenza: 'San Demetrio Corone',
      professione: 'Segretaria comunale',
      flag: [], alias: '',
      nota_cl1: '', nota_cl3: 'Ha accesso agli atti del Comune. Potrebbe verificare eventuali variazioni catastali sui terreni Strigari negli ultimi anni.', nota_cl5: '',
    },
    {
      id: 'P019',
      cognome_pubblico:    'Torchia',
      nome_pubblico:       'Giovanni',
      cognome_riservato:   null, nome_riservato: null,
      nato: '1948-04-14', luogo_nascita: 'San Demetrio Corone', residenza: 'Brunetti (contrada)',
      professione: 'Casaro — residente contrada Brunetti',
      flag: ['testimone'], alias: 'Giannino',
      nota_cl1: 'Testimone secondario',
      nota_cl3: 'Ha sentito "un motore a luci spente" a Brunetti verso mezzanotte del 12/07. "Un furgone bianco. Poi è ripartito." Non ha visto la targa.',
      nota_cl5: '',
    },
    {
      id: 'P020',
      cognome_pubblico:    'Mazzuca',
      nome_pubblico:       'Elia',
      cognome_riservato:   null, nome_riservato: null,
      nato: '1990-12-31', luogo_nascita: 'San Demetrio Corone', residenza: 'San Demetrio Corone',
      professione: 'Barista — Bar Central, Piazza Crispi',
      flag: [], alias: '',
      nota_cl1: '', nota_cl3: 'Contraddice la voce circolata: dice di NON aver visto il Professore la sera del 12/07 al bar. Ma il Professore di solito ci passava.', nota_cl5: '',
    },
    /* Persone reali incorporate — NON MODIFICARE I NOMI */
    { id:'P021', cognome_pubblico:'Sposato',  nome_pubblico:'Luca',     cognome_riservato:null, nome_riservato:null, nato:'1988-02-20', luogo_nascita:'Acri',               residenza:'San Demetrio Corone', professione:'Impiegato comunale',         flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P022', cognome_pubblico:'Lamirata', nome_pubblico:'Giuseppe', cognome_riservato:null, nome_riservato:null, nato:'1975-07-11', luogo_nascita:'San Demetrio Corone', residenza:'San Demetrio Corone', professione:'Artigiano',                  flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P023', cognome_pubblico:'Bellucci', nome_pubblico:'Riccardo', cognome_riservato:null, nome_riservato:null, nato:'1992-12-03', luogo_nascita:'Rossano',             residenza:'San Demetrio Corone', professione:'Studente',                   flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P024', cognome_pubblico:'Solano',   nome_pubblico:'Adriano',  cognome_riservato:null, nome_riservato:null, nato:'1983-05-29', luogo_nascita:'San Demetrio Corone', residenza:'Cosenza',             professione:'Tecnico informatico',         flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P025', cognome_pubblico:'Fusaro',   nome_pubblico:'Giuseppe', cognome_riservato:null, nome_riservato:null, nato:'1967-08-14', luogo_nascita:'Lungro',              residenza:'San Demetrio Corone', professione:'Pensionato',                 flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    /* Soggetti aggiuntivi */
    { id:'P026', cognome_pubblico:'Scorpino',    nome_pubblico:'Elvira',    cognome_riservato:null, nome_riservato:null, nato:'1984-06-09', luogo_nascita:'San Demetrio Corone', residenza:'San Demetrio Corone', professione:'Parrucchiera',                flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P027', cognome_pubblico:'Perri',        nome_pubblico:'Carmela',   cognome_riservato:null, nome_riservato:null, nato:'1969-11-14', luogo_nascita:'Acri',               residenza:'San Demetrio Corone', professione:'Commerciante — abbigliamento',flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P028', cognome_pubblico:'Cristofaro',   nome_pubblico:'Mario',     cognome_riservato:null, nome_riservato:null, nato:'1956-03-28', luogo_nascita:'San Demetrio Corone', residenza:'San Demetrio Corone', professione:'Meccanico',                  flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P029', cognome_pubblico:'Veltri',       nome_pubblico:'Concetta',  cognome_riservato:null, nome_riservato:null, nato:'1979-08-22', luogo_nascita:'Corigliano Calabro', residenza:'San Demetrio Corone', professione:'Infermiera',                 flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P030', cognome_pubblico:'Frasca',       nome_pubblico:'Antonio',   cognome_riservato:null, nome_riservato:null, nato:'1944-01-06', luogo_nascita:'San Demetrio Corone', residenza:'Macchia Albanese',   professione:'Pensionato',                 flag:[], alias:'Ntoni', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P031', cognome_pubblico:'Canino',       nome_pubblico:'Rocco',     cognome_riservato:null, nome_riservato:null, nato:'1987-09-17', luogo_nascita:'San Demetrio Corone', residenza:'San Demetrio Corone', professione:'Operaio edile',              flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P032', cognome_pubblico:'Brutto',       nome_pubblico:'Marianna',  cognome_riservato:null, nome_riservato:null, nato:'1995-04-30', luogo_nascita:'Cosenza',             residenza:'San Demetrio Corone', professione:'Studentessa — Unical',       flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P033', cognome_pubblico:'Mazzuca',      nome_pubblico:'Pasquale',  cognome_riservato:null, nome_riservato:null, nato:'1961-12-11', luogo_nascita:'San Demetrio Corone', residenza:'Piedigallo (contrada)', professione:'Allevatore',               flag:[], alias:'Pascale', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P034', cognome_pubblico:'Torchia',      nome_pubblico:'Assunta',   cognome_riservato:null, nome_riservato:null, nato:'1950-07-03', luogo_nascita:'San Demetrio Corone', residenza:'San Demetrio Corone', professione:'Pensionata',                 flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P035', cognome_pubblico:'Stranges',     nome_pubblico:'Filomena',  cognome_riservato:null, nome_riservato:null, nato:'1976-02-14', luogo_nascita:'Lungro',              residenza:'San Demetrio Corone', professione:"Segretaria — Collegio Sant'Adriano", flag:[], alias:'', nota_cl1:'', nota_cl3:"Ha ricevuto una chiamata dal Professore la sera del 12/07 (T008): 'Passo stanotte?' Non è mai passato. Si è mostrata turbata durante l'interrogatorio.", nota_cl5:'' },
    { id:'P036', cognome_pubblico:'Scarpino',     nome_pubblico:'Domenica',  cognome_riservato:null, nome_riservato:null, nato:'1939-10-19', luogo_nascita:'San Demetrio Corone', residenza:'San Demetrio Corone', professione:'Pensionata',                 flag:[], alias:'Mena', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P037', cognome_pubblico:'Plastino',     nome_pubblico:'Vincenzo',  cognome_riservato:null, nome_riservato:null, nato:'1982-05-25', luogo_nascita:'Acri',               residenza:'San Demetrio Corone', professione:'Elettricista',               flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P038', cognome_pubblico:'Carnevale',    nome_pubblico:'Saverio',   cognome_riservato:null, nome_riservato:null, nato:'1953-09-08', luogo_nascita:'San Demetrio Corone', residenza:'Mattarise (contrada)', professione:'Olivicoltore',              flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P039', cognome_pubblico:'Pangallo',     nome_pubblico:'Luigi',     cognome_riservato:null, nome_riservato:null, nato:'1948-11-30', luogo_nascita:'San Demetrio Corone', residenza:'San Demetrio Corone', professione:'Pensionato — ex vigile urbano', flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P040', cognome_pubblico:'Perri',        nome_pubblico:'Saverio',   cognome_riservato:null, nome_riservato:null, nato:'1991-03-07', luogo_nascita:'Rossano',             residenza:'San Demetrio Corone', professione:'Barista',                    flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    /* Soggetti storici / deceduti */
    { id:'P041', cognome_pubblico:'Strigari',     nome_pubblico:'Filippo',   cognome_riservato:null, nome_riservato:null, nato:'1908-01-14', luogo_nascita:'San Demetrio Corone', residenza:'[DECEDUTO 1943 — disperso in guerra]', professione:'Proprietario terriero', flag:['chiave'], alias:'', nota_cl1:'Deceduto/disperso 1943', nota_cl3:"Padre di Costantino Strigari. Originario proprietario dell'Anello. Partì per il fronte nel 1943 con un telegramma misterioso (D007). Non tornò mai.", nota_cl5:"L'Anello che il Professore stava restituendo era originariamente suo. Il telegramma del 1943 dice 'sarà lui a trovarvi' — chi era 'lui'? Il Professore era destinato a trovare l'Anello?" },
    { id:'P042', cognome_pubblico:'Veltri',       nome_pubblico:'Carmelo Sr.',cognome_riservato:null, nome_riservato:null, nato:'1918-05-20', luogo_nascita:'San Demetrio Corone', residenza:'[DECEDUTO 1995]', professione:'Ex podestà', flag:[], alias:'', nota_cl1:'Deceduto 1995', nota_cl3:'', nota_cl5:'' },
    { id:'P043', cognome_pubblico:'Cristofaro',   nome_pubblico:'Annunziata', cognome_riservato:null, nome_riservato:null, nato:'1925-08-15', luogo_nascita:'San Demetrio Corone', residenza:'[DECEDUTA 2010]', professione:'Sarta', flag:[], alias:'Nunzia', nota_cl1:'Deceduta 2010', nota_cl3:'', nota_cl5:'' },
    /* Emigrati */
    { id:'P044', cognome_pubblico:'Scorpino',     nome_pubblico:'Aldo',      cognome_riservato:null, nome_riservato:null, nato:'1965-04-18', luogo_nascita:'San Demetrio Corone', residenza:'Milano (emigrato)', professione:'Ingegnere', flag:[], alias:'', nota_cl1:'Emigrato Nord Italia', nota_cl3:'', nota_cl5:'' },
    { id:'P045', cognome_pubblico:'Frasca',       nome_pubblico:'Maria',     cognome_riservato:null, nome_riservato:null, nato:'1970-09-25', luogo_nascita:'San Demetrio Corone', residenza:'Germania (emigrata)', professione:'Operaia — Francoforte', flag:[], alias:'', nota_cl1:'Emigrata Germania', nota_cl3:'', nota_cl5:'' },
    { id:'P046', cognome_pubblico:'Canino',       nome_pubblico:'Pietro',    cognome_riservato:null, nome_riservato:null, nato:'1977-06-12', luogo_nascita:'San Demetrio Corone', residenza:'San Demetrio Corone', professione:'Idraulico',                  flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P047', cognome_pubblico:'Mazzuca',      nome_pubblico:'Rosa',      cognome_riservato:null, nome_riservato:null, nato:'1960-10-04', luogo_nascita:'Lungro',              residenza:'San Demetrio Corone', professione:'Ricamatrice — artigiana',    flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P048', cognome_pubblico:'Stranges',     nome_pubblico:'Giuseppe',  cognome_riservato:null, nome_riservato:null, nato:'1943-02-28', luogo_nascita:'San Demetrio Corone', residenza:'[DECEDUTO 2018]', professione:'Pastore', flag:[], alias:'Peppino il Pastore', nota_cl1:'Deceduto 2018', nota_cl3:'', nota_cl5:'' },
    { id:'P049', cognome_pubblico:'Torchia',      nome_pubblico:'Leonardo',  cognome_riservato:null, nome_riservato:null, nato:'1985-07-16', luogo_nascita:'Cosenza',             residenza:'San Demetrio Corone', professione:'Geometra',                   flag:[], alias:'', nota_cl1:'', nota_cl3:'', nota_cl5:'' },
    { id:'P050', cognome_pubblico:'Scarpino',     nome_pubblico:'Emilio',    cognome_riservato:null, nome_riservato:null, nato:'1934-11-22', luogo_nascita:'San Demetrio Corone', residenza:'[DECEDUTO 2005]', professione:'Falegname artigiano', flag:[], alias:'', nota_cl1:'Deceduto 2005', nota_cl3:'', nota_cl5:'' },
  ],

  // ── VEICOLI ──────────────────────────────────────────────
  veicoli: [
    { id:'V001', targa:'CS 123 AA', tipo:'auto',    marca:'Fiat',        modello:'Punto',     colore:'Grigio',  anno:2009, proprietario_id:'P001', nota_cl2:'Trovato parcheggiato Via D. Mauro il 13/07 ore 07:00. Chiavi nell\'auto. Portafoglio nell\'auto. Borsa sul sedile posteriore: VUOTA.' },
    { id:'V002', targa:'CS 456 BB', tipo:'auto',    marca:'Alfa Romeo',  modello:'147',       colore:'Nero',    anno:2014, proprietario_id:'P004', nota_cl2:'Telecamera: Via Collegio 12/07 ore 22:10. [VERIFICATO — rientrava a casa. PISTA CHIUSA]' },
    { id:'V003', targa:'CZ 789 CC', tipo:'moto',    marca:'Honda',       modello:'SH 150',    colore:'Bianco',  anno:2018, proprietario_id:'P005', nota_cl2:'' },
    { id:'V004', targa:'KR 321 DD', tipo:'furgone', marca:'Fiat',        modello:'Doblò',     colore:'Bianco',  anno:2012, proprietario_id:'P017', nota_cl2:'SEGNALATO zona Brunetti, 12/07 ~23:30. Fonte: Torchia Giovanni (P019). Proprietario: Pangallo Bruno. Non verificato.' },
    { id:'V005', targa:'CS 654 EE', tipo:'auto',    marca:'Lancia',      modello:'Ypsilon',   colore:'Argento', anno:2017, proprietario_id:'P008', nota_cl2:'' },
    { id:'V006', targa:'CS 987 FF', tipo:'auto',    marca:'Volkswagen',  modello:'Golf',      colore:'Blu',     anno:2020, proprietario_id:'P002', nota_cl2:'' },
    { id:'V007', targa:'CS 111 GG', tipo:'auto',    marca:'Fiat',        modello:'Panda 4x4', colore:'Verde',   anno:2005, proprietario_id:'P006', nota_cl2:'AVVISTATA zona Trappeto 12/07 ore 19:00, tre ore prima della scomparsa. Veltri non ha spiegato.' },
    { id:'V008', targa:'CS 222 HH', tipo:'agricolo',marca:'Same',        modello:'Frutteto',  colore:'Arancio', anno:1998, proprietario_id:'P038', nota_cl2:'Trattore Carnevale — terreni Mattarise. Nessuna rilevanza.' },
    { id:'V009', targa:'CS 333 II', tipo:'moto',    marca:'Vespa',       modello:'ET4 150',   colore:'Rosso',   anno:2001, proprietario_id:'P012', nota_cl2:'Ex maresciallo Torchia — mezzo personale.' },
    { id:'V010', targa:'CS 444 LL', tipo:'agricolo',marca:'Lamborghini', modello:'R3 EVO',    colore:'Verde',   anno:2008, proprietario_id:'P033', nota_cl2:'Trattore Mazzuca — contrada Piedigallo.' },
    { id:'V011', targa:'CS 555 MM', tipo:'furgone', marca:'Mercedes',    modello:'Sprinter',  colore:'Bianco',  anno:2016, proprietario_id:'P015', nota_cl2:'' },
    { id:'V012', targa:'CS 666 NN', tipo:'auto',    marca:'Seat',        modello:'Ibiza',     colore:'Grigio',  anno:2019, proprietario_id:'P035', nota_cl2:'Parcheggiata al Collegio la sera del 12/07. Stranges Filomena era al lavoro fino alle 20:00.' },
  ],

  // ── TELEFONATE ───────────────────────────────────────────
  telefonate: [
    { id:'T001', data:'2026-07-10 18:32', da_id:'P001', a_id:'P002', durata:'4m 12s', critica:false, nota_cl2:'Ultima chiamata confermata con Strigari. Accordo consegna Anello. Mercoledì 12, ore 21:00, Via D. Mauro.' },
    { id:'T002', data:'2026-07-10 19:05', da_id:'P004', a_id:'P001', durata:'1m 48s', critica:false, nota_cl2:'Scorpino → Professore. [Dichiarazione: testamento padre — PISTA CHIUSA ma vedi T005]' },
    { id:'T003', data:'2026-07-11 09:10', da_id:'P003', a_id:'P001', durata:'2m 03s', critica:false, nota_cl2:'Pangallo M.G. → Professore. Conversazione ordinaria.' },
    { id:'T004', data:'2026-07-12 20:55', da_id:'P001', a_id:'P005', durata:'0m 45s', critica:true,  nota_cl2:'ULTIMA CHIAMATA REGISTRATA. "Vado a portare la cosa. Ci vediamo dopo."' },
    { id:'T005', data:'2026-07-13 08:30', da_id:'P002', a_id:'P004', durata:'6m 10s', critica:true,  nota_cl2:'INTERCETTATA. Strigari → Scorpino. "L\'anello non è arrivato." — Scorpino: "Non coinvolgermi più." RIAPRIRE PISTA.' },
    { id:'T006', data:'2026-07-09 15:20', da_id:'P004', a_id:'P001', durata:'3m 30s', critica:false, nota_cl2:'Prima chiamata Scorpino → Professore. [Testamento padre — vedi T005]' },
    { id:'T007', data:'2026-07-08 11:45', da_id:'P006', a_id:'P002', durata:'8m 22s', critica:true,  nota_cl2:'ATTENZIONE: Veltri → Strigari, 4 giorni prima della scomparsa. 8 minuti. Contenuto ignoto. PISTA APERTA.' },
    { id:'T008', data:'2026-07-12 19:30', da_id:'P001', a_id:'P035', durata:'1m 10s', critica:false, nota_cl2:'Professore → Stranges Filomena (segretaria Collegio). "Passo stanotte?" Non è mai passato.' },
    { id:'T009', data:'2026-07-13 07:15', da_id:'P005', a_id:'P005', durata:'—',      critica:false, nota_cl2:'Stranges Rocco chiama familiari del Professore. Segnala anomalia.' },
  ],

  // ── DOCUMENTI (CL4) ──────────────────────────────────────
  documenti: [
    { id:'D001', titolo:'Lettera riservata — al Signor Strigari', data:'08 luglio 2026', tipo:'Corrispondenza', classificazione:'RISERVATO', nota_archivio:'Originale acquisito 15/07/2026.',
      testo:`Egregio Signor Strigari,

in seguito ai nostri accordi telefonici del 5 luglio, Le confermo
l'incontro per mercoledì 12 luglio, verso le ore 21:00,
nei pressi di Via Domenico Mauro.

Come Le ho anticipato, l'oggetto in mio possesso appartiene
di diritto alla Sua famiglia.
Lo custodisco dal 2025, quando lo ho ritrovato
tra i materiali appartenuti a mio padre.

Non ho ritenuto corretto trattenerlo ulteriormente.

Confido nella Sua discrezione circa questa restituzione,
poiché la storia dell'oggetto è... delicata.

Distinti saluti,`,
      firma:'[Il Professore — identità riservata CL.5]' },

    { id:'D002', titolo:"Verbale di testimonianza — Stranges Rocco", data:'13 luglio 2026', tipo:'Verbale', classificazione:'USO INTERNO', nota_archivio:'Redatto ore 10:30. Verbalizzante: Sposato L.',
      testo:`Il sottoscritto Stranges Rocco dichiara:

"La sera del 12 luglio ho ricevuto una telefonata verso le 20:55.
Era il Professore. Mi ha detto: 'Vado a portare la cosa.
Ci vediamo dopo.' Sembrava tranquillo, forse nervoso.

Verso le 21:40 l'ho visto passare in Via D. Mauro, a piedi,
con una borsa di tela. Andava verso il Collegio.
Gli ho fatto cenno. Ha risposto.

La mattina dopo la macchina era ancora lì.
Ho capito che qualcosa non andava."`,
      firma:'Stranges Rocco' },

    { id:'D003', titolo:"Nota storica — L'Anello Strigari", data:'20 giugno 2026', tipo:'Nota storica', classificazione:'ARCHIVIO', nota_archivio:'Redatta dal soggetto a uso personale.',
      testo:`Oggetto: catalogazione — Anello sigillare, famiglia Strigari.

Materiale: argento brunito, manifattura XVIII sec.
Castone: lettera S gotica sormontata da corona a cinque punte.
Gambo interno: "STRIGARI — MEMENTO".

Andato perduto durante la Seconda Guerra Mondiale.
Il padre di mio padre lo trovò in un campo nel 1944
e non sapendo a chi appartenesse lo conservò.

Ora so a chi appartiene.

Non ho ancora capito perché Strigari abbia risposto:
"Finalmente. Sapevo che sarebbe tornato da noi."
Come poteva saperlo?`,
      firma:'[Omissis — CL.5]' },

    { id:'D004', titolo:'Nota interna — pista Scorpino (RIAPERTA)', data:'19 luglio 2026', tipo:'Nota investigativa', classificazione:'RISERVATO', nota_archivio:'Aggiornata dopo acquisizione T005.',
      testo:`Il notaio Scorpino (P004) aveva dichiarato di aver chiamato
il Professore solo per questioni di eredità.

AGGIORNAMENTO 19/07: intercettazione T005 del 13/07 rivela
che Scorpino era a conoscenza di qualcosa di più.
"Non coinvolgermi più in questa storia."

Questo contraddice la versione fornita.
PISTA RIAPERTA. Richiedere convocazione urgente.`,
      firma:'K.A.R.I. — Responsabile Caso 27' },

    { id:'D005', titolo:"Appunto manoscritto — rinvenuto in V001", data:'13 luglio 2026', tipo:'Prova materiale', classificazione:'RISERVATO CL.4', nota_archivio:'Sedile passeggero. Scrittura compatibile con soggetto.',
      testo:`[Scritto a mano su carta strappata da un'agenda]

Strigari — h 21:00 — Via D. Mauro

Ricordare:
- Non parlare dell'altro
- Consegnare solo l'anello, niente altro
- Se fa domande sull'incisione, non rispondere

Cosa sa Veltri???`,
      firma:'[Omissis]' },

    { id:'D006', titolo:'Dichiarazione — Pangallo Maria Grazia (2ª)', data:'14 luglio 2026', tipo:'Verbale', classificazione:'USO INTERNO', nota_archivio:'Si è mostrata nervosa durante tutto il colloquio.',
      testo:`"L'ho visto passare sotto casa, verso le 21:30.
Camminava di fretta. Portava una borsa.

Non l'ho fermato perché pensavo andasse a fare una commissione.

Mio marito quella sera era a Brunetti, nei terreni.
È rientrato dopo mezzanotte. Me l'ha detto lui.

No, non so perché ci fosse il furgone a quell'ora.
I terreni non sono lì vicino.
Forse è passato per controllare qualcosa."

[Nota: risposta sull'orario del marito arrivata troppo in fretta,
come se fosse stata preparata in precedenza.]`,
      firma:'Pangallo Maria Grazia' },

    { id:'D007', titolo:'Telegramma — Strigari Filippo, agosto 1943', data:'12 agosto 1943', tipo:'Documento storico', classificazione:'ARCHIVIO STORICO', nota_archivio:'Originale — acquisito con fascicolo famiglia Strigari.',
      testo:`TELEGRAMMA — REGIO ESERCITO ITALIANO
Da: Strigari Filippo, 41° Regg. Fanteria
A: Strigari Costanza, San Demetrio Corone

CARA COSTANZA STOP
PARTENZA IMMINENTE STOP
HO AFFIDATO L'ANELLO A PERSONA FIDATA STOP
TORNERÀ A VOI QUANDO SARÀ IL MOMENTO STOP
NON CERCATE STOP
SARÀ LUI A TROVARVI STOP
ABBRACCIO I BAMBINI STOP
FILIPPO

[Filippo Strigari non tornò mai dal fronte.
Fu dichiarato disperso nel 1945.]`,
      firma:'Archivio di Stato — fascicolo Strigari' },

    { id:'D008', titolo:'Nota operativa — avvistamento V007 zona Trappeto', data:'15 luglio 2026', tipo:'Nota investigativa', classificazione:'RISERVATO', nota_archivio:'PISTA APERTA.',
      testo:`Auto V007 (Veltri, P006) avvistata zona Trappeto
il 12/07 ore 19:00 — tre ore prima della scomparsa.

Il Trappeto dista ~800m dal percorso del soggetto.

Veltri: "Non ricordo i miei spostamenti quella sera."

ANOMALIA: telefonata Veltri → Strigari del 08/07 (T007,
8 minuti), 4 giorni prima. Contenuto ignoto.

La nota manoscritta D005 del soggetto riporta:
"Cosa sa Veltri???"

Richiedere: verifica telecamere zona Trappeto,
tabulati completi Veltri, rapporti patrimoniali
Veltri-Strigari ultimi 10 anni.`,
      firma:'K.A.R.I. — Caso 27' },

    { id:'D009', titolo:"Inventario oggetti rinvenuti in V001", data:'13 luglio 2026', tipo:'Prova materiale', classificazione:'RISERVATO CL.4', nota_archivio:'Sopralluogo ore 09:30 del 13/07.',
      testo:`Oggetti in Fiat Punto CS 123 AA:

1. Appunto manoscritto (D005) — sedile passeggero
2. Portafoglio: documenti + 47€ in contanti
3. Chiavi di casa (mazzo completo)
4. Caricatore telefono — senza telefono
5. Libro: "Cardarelli — Poesie" edizione 1948
6. Borsa di tela — sedile posteriore: VUOTA

ELEMENTO CRITICO:
La borsa è VUOTA.
Il soggetto non aveva portafoglio né chiavi.
Aveva il telefono (ultima chiamata ore 20:55).
L'ANELLO NON ERA NELL'AUTO.
Il soggetto lo portava con sé quando è sparito.`,
      firma:'Sopralluogo K.A.R.I. — Sposato L.' },

    { id:'D010', titolo:'[CL.5] Note personali del soggetto — estratto', data:'2026 — data incerta', tipo:'Documento personale', classificazione:'TOP SECRET CL.5', nota_archivio:'Rinvenuto nell\'appartamento. Solo estratto autorizzato.',
      testo:`[Pagine classificate CL.5]
[Accesso completo: richiesta alla Direzione]

████████████████████████████████████████
████████████████████████████████████████

[...estratto autorizzato CL.5...]

"...non so cosa sappia Veltri dell'Anello.
La sua reazione al telefono mi ha turbato.
Ha detto 'lo sappiamo già da anni.'
Chi è 'noi'?

Ho paura che l'anello sia più di quello
che pensavo fosse. Forse non è solo
un oggetto di famiglia.

Forse è un segreto che qualcuno
non vuole che ritorni..."

████████████████████████████████████████`,
      firma:'[Omissis]' },
  ],

  // ── AUDIO (CL4) ──────────────────────────────────────────
  audio: [
    { id:'A001', titolo:'Testimonianza — Stranges Rocco (principale)', durata:'3:12', data:'13 luglio 2026',
      trascrizione:`[ore 10:30]
"...l'ho visto verso le 21:40. Andava verso il Collegio.
Portava una borsa di tela. Mi ha salutato con la mano.
Camminava veloce, come quando aveva fretta.
La mattina dopo la macchina era ancora lì.
Ho chiamato sua sorella. Poi i Carabinieri."` },
    { id:'A002', titolo:'Testimonianza — Pangallo Maria Grazia', durata:'2:44', data:'14 luglio 2026',
      trascrizione:`[ore 15:20]
"L'ho visto passare sotto casa. Di fretta.
Mio marito era a Brunetti. [pausa]
Dice di essere andato a controllare le pompe.
Rientrato verso mezzanotte.
[voce esitante]
Non so cosa stesse facendo là a quell'ora.
I campi non richiedono irrigazione di notte."` },
    { id:'A003', titolo:'Dichiarazione — Scorpino Raffaele (notaio)', durata:'4:05', data:'15 luglio 2026',
      trascrizione:`[ore 09:45]
"Ho chiamato il Professore due volte.
Questioni del testamento del padre.
Con la scomparsa non ho nulla a che fare.
Strigari? Cliente storico. Questioni patrimoniali.
Non mi chieda altro. Segreto professionale."` },
    { id:'A004', titolo:'Testimonianza spontanea — Torchia Giovanni (Brunetti)', durata:'1:58', data:'16 luglio 2026',
      trascrizione:`[ore 14:00]
"Stavo rientrando dal casolare, mezzanotte passata.
Ho sentito un motore. Luci spente.
Un furgone bianco. Poi è ripartito.
Non ho visto la targa. Mi sono insospettito
ma non ho fatto niente. Chi vuoi che chiami
a quell'ora?"` },
    { id:'A005', titolo:'[INTERCETTATA] Strigari / Scorpino — T005', durata:'6:10', data:'13 luglio 2026',
      trascrizione:`[ore 08:30 — autorizzazione giudiziaria]

STRIGARI: "...non è venuto."
SCORPINO: "Lo so. Ho saputo stamattina."
STRIGARI: "L'anello non è arrivato."
SCORPINO: "Forse ha cambiato idea."
STRIGARI: [pausa] "Il Professore non cambiava idea."
SCORPINO: "Non coinvolgermi più in questa storia,
           Costantino. Non più."
STRIGARI: "Non puoi tirarti fuori. Sai quello—"
[Chiamata interrotta]

[NOTA: questo scambio contraddice la versione
di Scorpino. RIAPRIRE PISTA URGENTE.]` },
  ],

  // ── DOSSIER CL5 ──────────────────────────────────────────
  dossier: {
    nome_completo:    'Vincenzo Bellusci',
    data_nascita:     '14 marzo 1951',
    luogo_nascita:    'San Demetrio Corone',
    professione:      "Insegnante di lettere — Collegio Sant'Adriano (in pensione dal 2016)",
    stato:            'SCOMPARSO — notte 12-13 luglio 2026',
    sintesi:          "Bellusci si stava recando a restituire l'Anello sigillare Strigari (XVIII sec.) a Costantino Strigari. Appuntamento ore 21:00, Via Domenico Mauro. Non è mai arrivato. La borsa nell'auto era vuota: aveva l'Anello con sé.",
    piste_aperte:     "— VELTRI: presenza zona Trappeto + chiamata Strigari + nota D005. PRIORITÀ ALTA\n— PANGALLO Bruno: furgone a Brunetti mezzanotte, nessun alibi verificabile\n— SCORPINO: intercettazione T005 contraddice la sua versione. RIAPRIRE",
    piste_chiuse:     "— Scorpino (prima versione): testamento padre. ORA RIAPERTA\n— Alfa Romeo Scorpino Via Collegio: verificato, rientrava a casa",
    elemento_critico: "La borsa nell'auto era VUOTA (D009). L'Anello non era nell'auto. È ancora là fuori.",
  },

  // ── TIMELINE ─────────────────────────────────────────────
  timeline: [
    { data:'1943 — agosto',       testo:'Strigari Filippo parte per il fronte lasciando il telegramma D007. L\'Anello scompare.' },
    { data:'1944 — estate',        testo:'Il padre del Professore trova un anello in un campo. Lo conserva.' },
    { data:'1943-1945',            testo:'Strigari Filippo dichiarato disperso in guerra. Non tornerà mai.' },
    { data:'2020',                 testo:'Muore il padre del Professore. Tra i suoi oggetti: l\'Anello Strigari.' },
    { data:'Autunno 2025',         testo:'<hl>Il Professore identifica l\'Anello</hl> e ne capisce la provenienza. Scrive la nota D003.' },
    { data:'5 luglio 2026',        testo:'Prima telefonata con Strigari. Accordo per la restituzione. Strigari: "Finalmente. Sapevo che sarebbe tornato da noi."' },
    { data:'8 luglio — 11:45',     testo:'<hlr>Veltri chiama Strigari</hlr> (T007, 8 minuti). Quattro giorni prima. Contenuto ignoto. PISTA APERTA.' },
    { data:'8 luglio 2026',        testo:'Il Professore scrive la lettera formale D001. Appuntamento mercoledì 12, ore 21:00.' },
    { data:'9 luglio — 15:20',     testo:'<hl>Prima chiamata Scorpino → Professore</hl> (T006). [Testamento padre — vedi T005]' },
    { data:'10 luglio — 18:32',    testo:'<hlr>Ultima telefonata Professore → Strigari</hlr> (T001, 4m 12s). Conferma appuntamento.' },
    { data:'10 luglio — 19:05',    testo:'<hl>Seconda chiamata Scorpino → Professore</hl> (T002).' },
    { data:'12 luglio — 19:00',    testo:'<hlr>Veltri (V007) avvistato zona Trappeto.</hlr> Non ha spiegato. PISTA APERTA.' },
    { data:'12 luglio — 19:30',    testo:'Professore chiama Stranges Filomena al Collegio (T008). "Passo stanotte?" Non è mai passato.' },
    { data:'12 luglio — 20:55',    testo:'<hlr>ULTIMA CHIAMATA.</hlr> Professore → Stranges Rocco: "Vado a portare la cosa."' },
    { data:'12 luglio — 21:00',    testo:'V001 parcheggiato Via D. Mauro. Chiavi, portafoglio, borsa vuota lasciati nell\'auto.' },
    { data:'12 luglio — 21:30',    testo:'Pangallo M.G. lo vede passare. Borsa di tela. Di fretta.' },
    { data:'12 luglio — 21:40',    testo:'<hlr>ULTIMO AVVISTAMENTO.</hlr> Stranges Rocco lo vede diretto verso il Collegio.' },
    { data:'12 luglio — 22:10',    testo:'Alfa Romeo Scorpino (V002) in Via Collegio. [Verificato — rientrava a casa]' },
    { data:'12 luglio — 23:30',    testo:'<hl>Furgone Pangallo (V004)</hl> a Brunetti. Fonte: Torchia Giovanni. Non verificato.' },
    { data:'13 luglio — 07:00',    testo:'V001 ancora fermo. Stranges Rocco chiama i familiari e i Carabinieri.' },
    { data:'13 luglio — 08:30',    testo:'<hlr>INTERCETTAZIONE T005.</hlr> Strigari → Scorpino: "L\'anello non è arrivato." — RIAPRIRE PISTA.' },
    { data:'14 luglio 2026',       testo:'<hlr>Apertura Caso 27/2026 — Operazione Anello. Attivato sistema K.A.R.I.</hlr>' },
    { data:'15 luglio 2026',       testo:'Sopralluogo Brunetti: nessuna traccia. Inventario V001 (D009): BORSA VUOTA.' },
    { data:'16 luglio 2026',       testo:'Torchia Giovanni testimonia spontaneamente: furgone bianco a luci spente.' },
    { data:'18 luglio 2026',       testo:'Pista Scorpino archiviata (prima versione). RIAPERTA 19/07 per T005.' },
  ],

  // ── FINALE CL6 ───────────────────────────────────────────
  finale_testo: `VINCENZO BELLUSCI — 14 marzo 1951.

Quella sera portava con sé l'Anello Strigari.
La borsa nell'auto era vuota: lo aveva già preso.

Ha percorso Via Domenico Mauro a piedi,
verso il centro storico, verso il Collegio di Sant'Adriano —
il luogo dove aveva insegnato per trent'anni.

Qualcuno sapeva che stava arrivando.

L'Anello è ancora là fuori.
Trovi chi ce l'ha portato via.

— K.A.R.I. / Caso 27/2026 / Operazione Anello —`,

  // ── ADMIN FLAGS CL6 ──────────────────────────────────────
  admin_flags: [
    { id:'P001', soggetto:'BELLUSCI Vincenzo',  flag:'SCOMPARSO',        priorita:'CRITICA', nota:'Borsa vuota: aveva l\'Anello. Non è arrivato da Strigari.' },
    { id:'P006', soggetto:'VELTRI Carmelo',      flag:'SORVEGLIATO',      priorita:'ALTA',    nota:'Zona Trappeto + T007 + D005. Spiegazioni insufficienti.' },
    { id:'P017', soggetto:'PANGALLO Bruno',       flag:'DA INTERROGARE',   priorita:'MEDIA',   nota:'Furgone a Brunetti mezzanotte. Alibi non verificabile.' },
    { id:'P004', soggetto:'SCORPINO Raffaele',    flag:'PISTA RIAPERTA',   priorita:'ALTA',    nota:'T005: "Non coinvolgermi più." Sapeva qualcosa.' },
    { id:'P002', soggetto:'STRIGARI Costantino',  flag:'INFORMATO',        priorita:'MEDIA',   nota:'"Sapevo che sarebbe tornato." Come lo sapeva?' },
    { id:'V004', soggetto:'Furgone KR 321 DD',    flag:'DA LOCALIZZARE',   priorita:'MEDIA',   nota:'Brunetti mezzanotte. GPS non disponibile.' },
  ],
};

/* ============================================================
   FUNZIONE CHIAVE: prepara i dati per il client
   filtrando in base alla clearance della squadra.
   Il nome P001 viene rivelato SOLO a CL5+.
   ============================================================ */
function preparaDatiPerClearance(clearance) {
  const dati = {};

  // CL1: persone con dati pubblici (identità P001 oscurata)
  dati.persone = ARCHIVIO.persone.map(p => {
    const cognome = (clearance >= 5 && p.cognome_riservato) ? p.cognome_riservato : p.cognome_pubblico;
    const nome    = (clearance >= 5 && p.nome_riservato)    ? p.nome_riservato    : p.nome_pubblico;
    const record  = {
      id:          p.id,
      cognome,
      nome,
      nato:        p.nato,
      luogo_nascita: p.luogo_nascita,
      residenza:   p.residenza,
      professione: p.professione,
      flag:        p.flag,
      alias:       p.alias,
      nota:        p.nota_cl1 || '',
    };
    if (clearance >= 3) record.nota = p.nota_cl3 || p.nota_cl1 || '';
    if (clearance >= 5) record.nota = p.nota_cl5 || p.nota_cl3 || p.nota_cl1 || '';
    return record;
  });

  // CL2+: veicoli
  if (clearance >= 2) {
    dati.veicoli = ARCHIVIO.veicoli.map(v => ({
      id: v.id, targa: v.targa, tipo: v.tipo,
      marca: v.marca, modello: v.modello, colore: v.colore, anno: v.anno,
      proprietario_id: v.proprietario_id,
      nota: clearance >= 2 ? (v.nota_cl2 || '') : '',
    }));
  }

  // CL2+: telefonate (note visibili da CL2)
  if (clearance >= 2) {
    dati.telefonate = ARCHIVIO.telefonate.map(t => ({
      id: t.id, data: t.data, da_id: t.da_id, a_id: t.a_id, durata: t.durata,
      critica: t.critica,
      nota: t.nota_cl2 || '',
    }));
  }

  // CL4+: documenti, audio, foto (metadati)
  if (clearance >= 4) {
    dati.documenti = ARCHIVIO.documenti;
    dati.audio     = ARCHIVIO.audio;
  }

  // CL5+: dossier completo e timeline
  if (clearance >= 5) {
    dati.dossier  = ARCHIVIO.dossier;
    dati.timeline = ARCHIVIO.timeline;
  }

  // CL6+: finale e flags admin
  if (clearance >= 6) {
    dati.finale_testo = ARCHIVIO.finale_testo;
    dati.admin_flags  = ARCHIVIO.admin_flags;
  }

  return dati;
}

/* ============================================================
   DATABASE SQLite
   ============================================================ */
let db;

async function initDB() {
  const SQL = await initSqlJs();
  if (fs.existsSync(CONFIG.DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(CONFIG.DB_PATH));
    console.log('[DB] Caricato');
  } else {
    db = new SQL.Database();
    console.log('[DB] Creato nuovo database');
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS squadre (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      nome      TEXT    UNIQUE NOT NULL,
      password  TEXT    NOT NULL,
      clearance INTEGER DEFAULT 1,
      creata_il TEXT    DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS sessioni (
      id          TEXT    PRIMARY KEY,
      squadra_id  INTEGER NOT NULL,
      connessa    INTEGER DEFAULT 1,
      ip          TEXT,
      avviata_il  TEXT DEFAULT (datetime('now')),
      ultima_att  TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS registro (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      squadra_id    INTEGER,
      tipo          TEXT,
      dettaglio     TEXT,
      clearance_pre INTEGER,
      clearance_post INTEGER,
      ip            TEXT,
      ts            TEXT DEFAULT (datetime('now'))
    );
  `);

  for (const s of CONFIG.SQUADRE) {
    const exists = db.exec(`SELECT id FROM squadre WHERE nome = '${s.nome.replace(/'/g,"''")}'`);
    if (!exists.length || !exists[0].values.length) {
      const hash = bcrypt.hashSync(s.password, 10);
      db.run(`INSERT INTO squadre (nome, password) VALUES (?, ?)`, [s.nome, hash]);
      console.log(`[DB] Squadra: ${s.nome}`);
    }
  }
  saveDB();
  console.log('[DB] Pronto');
}

function saveDB() {
  const data = db.export();
  fs.mkdirSync(path.dirname(CONFIG.DB_PATH), { recursive: true });
  fs.writeFileSync(CONFIG.DB_PATH, Buffer.from(data));
}
setInterval(saveDB, 30000);

function dbGet(sql, params = []) {
  const res = db.exec(sql, params);
  if (!res.length || !res[0].values.length) return null;
  const { columns, values } = res[0];
  return Object.fromEntries(columns.map((c, i) => [c, values[0][i]]));
}
function dbAll(sql, params = []) {
  const res = db.exec(sql, params);
  if (!res.length) return [];
  const { columns, values } = res[0];
  return values.map(row => Object.fromEntries(columns.map((c, i) => [c, row[i]])));
}
function registra(squadra_id, tipo, dettaglio, cl_pre, cl_post, ip) {
  db.run(`INSERT INTO registro (squadra_id, tipo, dettaglio, clearance_pre, clearance_post, ip)
          VALUES (?,?,?,?,?,?)`, [squadra_id, tipo, dettaglio, cl_pre, cl_post, ip]);
  saveDB();
}

/* ============================================================
   EXPRESS + WEBSOCKET
   ============================================================ */
const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });
const clients = new Map();

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ secret: CONFIG.SESSION_SECRET, resave: false, saveUninitialized: false }));

function sendTo(ws, msg)   { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg)); }
function now()             { return new Date().toISOString(); }
function broadcastAdmin(m) {
  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN && clients.get(ws)?.isAdmin) ws.send(JSON.stringify(m));
  });
}

wss.on('connection', (ws, req) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  clients.set(ws, { isAdmin: false, ip });

  ws.on('message', raw => {
    let msg; try { msg = JSON.parse(raw); } catch { return; }
    handleMessaggio(ws, msg, ip);
  });

  ws.on('close', () => {
    const info = clients.get(ws);
    if (info?.sessione_id && !info.isAdmin) {
      db.run(`UPDATE sessioni SET connessa=0, ultima_att=datetime('now') WHERE id=?`, [info.sessione_id]);
      saveDB();
      broadcastAdmin({ type: 'squadra_disconnessa', nome: info.nome });
      registra(info.squadra_id, 'disconnessione', 'WebSocket chiuso', null, null, ip);
    }
    clients.delete(ws);
  });
});

function handleMessaggio(ws, msg, ip) {
  const info = clients.get(ws);

  switch (msg.type) {

    case 'admin_auth': {
      if (msg.password === CONFIG.ADMIN_PASSWORD) {
        clients.set(ws, { isAdmin: true, ip });
        sendTo(ws, { type: 'admin_ok' });
        sendTo(ws, { type: 'stato_completo', data: getStatoCompleto() });
      } else {
        sendTo(ws, { type: 'admin_err', messaggio: 'Password errata' });
      }
      break;
    }

    case 'squadra_auth': {
      const squadra = dbGet(`SELECT * FROM squadre WHERE nome = ?`, [msg.nome]);
      if (!squadra) { sendTo(ws, { type: 'auth_err', messaggio: 'Squadra non trovata' }); return; }
      if (!bcrypt.compareSync(msg.password, squadra.password)) {
        registra(squadra.id, 'login_fallito', 'Password errata', null, null, ip);
        broadcastAdmin({ type: 'evento', livello: 'warn', messaggio: `❌ Login fallito: ${squadra.nome}`, ts: now() });
        sendTo(ws, { type: 'auth_err', messaggio: 'Password errata' });
        return;
      }
      const sessione_id = uuid();
      db.run(`INSERT INTO sessioni (id, squadra_id, ip) VALUES (?,?,?)`, [sessione_id, squadra.id, ip]);
      saveDB();
      clients.set(ws, { isAdmin: false, squadra_id: squadra.id, nome: squadra.nome, sessione_id, ip });
      // Invia auth_ok + dati per la clearance attuale
      sendTo(ws, {
        type:     'auth_ok',
        nome:     squadra.nome,
        clearance: squadra.clearance,
        dati:     preparaDatiPerClearance(squadra.clearance),
      });
      registra(squadra.id, 'login', 'Accesso riuscito', squadra.clearance, null, ip);
      broadcastAdmin({ type: 'evento', livello: 'ok', messaggio: `✅ Login: ${squadra.nome} (CL.${squadra.clearance})`, ts: now() });
      broadcastAdmin({ type: 'stato_completo', data: getStatoCompleto() });
      break;
    }

    case 'codice': {
      if (!info?.squadra_id) { sendTo(ws, { type: 'codice_err', messaggio: 'Non autenticato' }); return; }
      const squadra   = dbGet(`SELECT * FROM squadre WHERE id=?`, [info.squadra_id]);
      const codice    = (msg.codice || '').trim().toUpperCase();
      const nuovaCL   = CONFIG.CODICI_CLEARANCE[codice];

      if (!nuovaCL) {
        registra(info.squadra_id, 'codice_errato', codice, squadra.clearance, null, ip);
        broadcastAdmin({ type: 'evento', livello: 'warn', messaggio: `⚠ Codice errato: ${info.nome} → "${codice}"`, ts: now() });
        sendTo(ws, { type: 'codice_err', messaggio: 'Codice non riconosciuto nel sistema' });
        return;
      }
      if (nuovaCL <= squadra.clearance) {
        sendTo(ws, { type: 'codice_warn', messaggio: `Clearance ${nuovaCL} già attiva` });
        return;
      }
      if (nuovaCL !== squadra.clearance + 1) {
        sendTo(ws, { type: 'codice_err', messaggio: `Sequenza errata — sblocca prima CL.${squadra.clearance + 1}` });
        return;
      }
      db.run(`UPDATE squadre SET clearance=? WHERE id=?`, [nuovaCL, info.squadra_id]);
      saveDB();
      registra(info.squadra_id, 'clearance_sbloccata', codice, squadra.clearance, nuovaCL, ip);
      broadcastAdmin({ type: 'evento', livello: 'ok', messaggio: `🔓 ${info.nome} → CL.${nuovaCL} sbloccata`, ts: now() });
      broadcastAdmin({ type: 'stato_completo', data: getStatoCompleto() });
      // Invia i nuovi dati corrispondenti alla clearance appena sbloccata
      sendTo(ws, {
        type:         'clearance_ok',
        nuova_clearance: nuovaCL,
        nuovi_dati:   preparaDatiPerClearance(nuovaCL),
      });
      break;
    }

    case 'ping': {
      if (info?.sessione_id) db.run(`UPDATE sessioni SET ultima_att=datetime('now') WHERE id=?`, [info.sessione_id]);
      sendTo(ws, { type: 'pong' });
      break;
    }

    case 'admin_set_clearance': {
      if (!info?.isAdmin) return;
      db.run(`UPDATE squadre SET clearance=? WHERE nome=?`, [msg.clearance, msg.nome]);
      saveDB();
      wss.clients.forEach(cl => {
        const ci = clients.get(cl);
        if (ci?.nome === msg.nome && cl.readyState === WebSocket.OPEN) {
          sendTo(cl, { type: 'clearance_forzata', clearance: msg.clearance, nuovi_dati: preparaDatiPerClearance(msg.clearance) });
        }
      });
      broadcastAdmin({ type: 'evento', livello: 'sys', messaggio: `⚙ Admin: ${msg.nome} → CL.${msg.clearance}`, ts: now() });
      broadcastAdmin({ type: 'stato_completo', data: getStatoCompleto() });
      break;
    }

    case 'admin_reset': {
      if (!info?.isAdmin) return;
      db.run(`UPDATE squadre SET clearance=1 WHERE nome=?`, [msg.nome]);
      saveDB();
      wss.clients.forEach(cl => {
        const ci = clients.get(cl);
        if (ci?.nome === msg.nome && cl.readyState === WebSocket.OPEN) {
          sendTo(cl, { type: 'clearance_forzata', clearance: 1, nuovi_dati: preparaDatiPerClearance(1) });
        }
      });
      broadcastAdmin({ type: 'evento', livello: 'warn', messaggio: `🔄 Reset: ${msg.nome} → CL.1`, ts: now() });
      broadcastAdmin({ type: 'stato_completo', data: getStatoCompleto() });
      break;
    }

    case 'admin_broadcast': {
      if (!info?.isAdmin) return;
      wss.clients.forEach(cl => {
        const ci = clients.get(cl);
        if (!ci?.isAdmin && cl.readyState === WebSocket.OPEN) sendTo(cl, { type: 'messaggio_admin', testo: msg.testo });
      });
      broadcastAdmin({ type: 'evento', livello: 'sys', messaggio: `📢 Broadcast: "${msg.testo}"`, ts: now() });
      break;
    }

    case 'admin_refresh': {
      if (!info?.isAdmin) return;
      sendTo(ws, { type: 'stato_completo', data: getStatoCompleto() });
      break;
    }
  }
}

function getStatoCompleto() {
  const squadre = dbAll(`SELECT id, nome, clearance, creata_il FROM squadre ORDER BY clearance DESC, nome`);
  const connesse = new Set();
  clients.forEach((info, ws) => {
    if (info?.squadra_id && !info.isAdmin && ws.readyState === WebSocket.OPEN) connesse.add(info.squadra_id);
  });
  const squadreArricchite = squadre.map(s => ({
    ...s, online: connesse.has(s.id),
    ultima_att: dbGet(`SELECT ultima_att FROM sessioni WHERE squadra_id=? ORDER BY ultima_att DESC LIMIT 1`, [s.id])?.ultima_att || null,
  }));
  const registro = dbAll(`
    SELECT r.ts, s.nome as squadra, r.tipo, r.dettaglio, r.clearance_pre, r.clearance_post
    FROM registro r LEFT JOIN squadre s ON r.squadra_id = s.id
    ORDER BY r.ts DESC LIMIT 100`);
  return { squadre: squadreArricchite, registro };
}

app.get('/api/stato', (req, res) => res.json(getStatoCompleto()));

initDB().then(() => {
  server.listen(CONFIG.PORT, () => {
    console.log(`\n╔══════════════════════════════════════════╗`);
    console.log(`║  K.A.R.I. — Kernel Archivistico         ║`);
    console.log(`║  http://localhost:${CONFIG.PORT}                ║`);
    console.log(`║  Admin: http://localhost:${CONFIG.PORT}/admin.html ║`);
    console.log(`╚══════════════════════════════════════════╝\n`);
    console.log(`  Admin password: ${CONFIG.ADMIN_PASSWORD}`);
    console.log(`  Squadre: ${CONFIG.SQUADRE.map(s => s.nome).join(', ')}\n`);
  });
});
