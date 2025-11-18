# Database Encryption Simulation Lab

A lightweight React-in-the-browser experience that walks through the three pillars of protecting data at rest:
column-level encryption functions, Transparent Data Encryption (TDE), and encrypting/decrypting sensitive fields
such as passwords or credit card numbers.

## Features

- **Column-level encryption playground** – Toggle which columns are encrypted and inspect how ciphertext replaces
  plaintext while analytics columns stay readable.
- **TDE explainer** – Flip Transparent Data Encryption on/off to see how disk-level protection complements column
  encryption.
- **Encryption sandbox** – Type in passwords and card numbers and produce ciphertext using CryptoJS AES, then paste
  encrypted payloads back in to decrypt them with the same key.
- **100% client-side** – Built without a backend; React and CryptoJS are loaded from CDNs so the experiment runs in
  any static hosting environment.

## Getting started

No build step is required. Open `index.html` in any modern browser or host the folder with a static server:

```bash
npx serve .
```

Then browse to the printed local URL. The lab automatically loads the scripts it needs.

## Customizing the exercise

- Update the `sampleRows` array in `app.jsx` with data that mirrors your own schema.
- Change the default key (`defaultKey` constant) to demo certificate rotation or key hierarchy lessons.
- Extend the UI with additional forms to represent key vault integrations or auditing telemetry.
