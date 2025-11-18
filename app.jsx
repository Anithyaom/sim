const sampleRows = [
  {
    id: 'ORD-9931',
    customer: 'River West',
    email: 'river@shopper.io',
    password: 'sunset#Skies',
    creditCard: '4111 1111 1111 1111',
    status: 'Ready to ship',
  },
  {
    id: 'ORD-9932',
    customer: 'Kai Lawson',
    email: 'kai@lawson.co',
    password: 'rainforest!22',
    creditCard: '5454 5454 5454 5454',
    status: 'Awaiting payment',
  },
  {
    id: 'ORD-9933',
    customer: 'Ava Patel',
    email: 'ava.patel@example.com',
    password: 'Aurora_91',
    creditCard: '3782 822463 10005',
    status: 'Completed',
  },
];

const defaultKey = 'TDE-demo-key-2025';

const maskValue = (value) => {
  if (!value) return '';
  return value.replace(/.(?=.{4})/g, '•');
};

const encryptValue = (value, key) => {
  if (!value) return '';
  return CryptoJS.AES.encrypt(value, key).toString();
};

const decryptValue = (cipher, key) => {
  if (!cipher) return '';
  try {
    const bytes = CryptoJS.AES.decrypt(cipher, key);
    const result = bytes.toString(CryptoJS.enc.Utf8);
    return result || 'Invalid key or ciphertext';
  } catch (error) {
    return 'Invalid key or ciphertext';
  }
};

const StepList = () => (
  <ul className="step-list">
    {[
      {
        title: 'Use column-level encryption functions',
        detail:
          'Lock down only the sensitive columns (passwords, card numbers) and keep analytical columns queryable.',
      },
      {
        title: 'Enable Transparent Data Encryption (TDE)',
        detail:
          'Protect the entire database at rest by encrypting files and backups automatically.',
      },
      {
        title: 'Encrypt/decrypt sensitive fields',
        detail:
          'Prove the protection by encrypting live data, storing the ciphertext, and decrypting it with the right key.',
      },
    ].map((step, index) => (
      <li key={step.title}>
        <div className="step-number">{index + 1}</div>
        <div>
          <strong>{step.title}</strong>
          <p>{step.detail}</p>
        </div>
      </li>
    ))}
  </ul>
);

const ColumnEncryptionLab = () => {
  const [columnConfig, setColumnConfig] = React.useState({
    email: true,
    password: true,
    creditCard: true,
  });
  const [key, setKey] = React.useState(defaultKey);

  const toggleColumn = (column) => {
    setColumnConfig((prev) => ({ ...prev, [column]: !prev[column] }));
  };

  const renderCell = (value, column) => {
    if (!columnConfig[column]) return value;
    const encrypted = encryptValue(value, key).slice(0, 20);
    return (
      <span className="badge" title={encryptValue(value, key)}>
        {`${encrypted}…`}
      </span>
    );
  };

  return (
    <div className="card">
      <div>
        <h2>Column-level encryption playground</h2>
        <p>
          Toggle built-in functions to encrypt specific columns. The data remains usable for operations that
          do not need the plaintext.
        </p>
      </div>

      <div className="form-grid">
        <label htmlFor="columnKey">Column master key</label>
        <input
          id="columnKey"
          value={key}
          onChange={(event) => setKey(event.target.value)}
          placeholder="Enter symmetric key"
        />
      </div>

      <div className="toggle-group" aria-label="Column level encryption toggles">
        {['email', 'password', 'creditCard'].map((column) => (
          <label className="toggle" key={column}>
            <input
              type="checkbox"
              checked={columnConfig[column]}
              onChange={() => toggleColumn(column)}
            />
            Encrypt {column === 'creditCard' ? 'credit card #' : column}
          </label>
        ))}
      </div>

      <div className="table-wrapper" role="region" aria-label="Customer data table">
        <table>
          <thead>
            <tr>
              <th>Order #</th>
              <th>Customer</th>
              <th>Email</th>
              <th>Password</th>
              <th>Credit card</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {sampleRows.map((row) => (
              <tr key={row.id}>
                <td>{row.id}</td>
                <td>{row.customer}</td>
                <td>{renderCell(row.email, 'email')}</td>
                <td>{renderCell(row.password, 'password')}</td>
                <td>{columnConfig.creditCard ? maskValue(row.creditCard) : row.creditCard}</td>
                <td>{row.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const TDECard = () => {
  const [enabled, setEnabled] = React.useState(true);

  return (
    <div className="tde-card">
      <div className={`status-chip ${enabled ? 'success' : 'warning'}`}>
        {enabled ? 'TDE is protecting data at rest' : 'TDE disabled'}
      </div>
      <h2>Transparent Data Encryption</h2>
      <p>
        The storage engine automatically encrypts database files, tempdb, and backups. Even if the disk is
        copied, the attacker sees ciphertext.
      </p>
      <ul>
        <li>✔ Automatic encryption/decryption during I/O</li>
        <li>✔ Uses certificate protected Database Encryption Key (DEK)</li>
        <li>✔ Works together with column-level encryption for layered defense</li>
      </ul>
      <button type="button" onClick={() => setEnabled((prev) => !prev)}>
        {enabled ? 'Simulate turning TDE off' : 'Enable TDE'}
      </button>
      <div className="highlight-box">
        {enabled
          ? 'TDE ON → Files on disk are unreadable without the server certificate.'
          : 'TDE OFF → Files on disk are stored as plaintext. Anyone with the file can read it.'}
      </div>
    </div>
  );
};

const EncryptionSandbox = () => {
  const [mode, setMode] = React.useState('encrypt');
  const [form, setForm] = React.useState({ password: '', card: '', key: defaultKey });
  const [output, setOutput] = React.useState(null);

  const handleChange = (event) => {
    const { name, value } = event.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = (event) => {
    event.preventDefault();
    if (!form.key) {
      setOutput({ error: 'Provide a key to encrypt/decrypt the data.' });
      return;
    }

    if (mode === 'encrypt') {
      setOutput({
        password: encryptValue(form.password, form.key),
        card: encryptValue(form.card, form.key),
        note: 'Store these ciphertexts in the database. They are useless without the same key.',
      });
    } else {
      setOutput({
        password: decryptValue(form.password, form.key),
        card: decryptValue(form.card, form.key),
        note: 'Only processes with the right key can see the original values.',
      });
    }
  };

  return (
    <div className="card">
      <div>
        <div className="mode-switch" role="tablist">
          {['encrypt', 'decrypt'].map((value) => (
            <button
              key={value}
              className={mode === value ? 'active' : ''}
              onClick={() => setMode(value)}
              role="tab"
              aria-selected={mode === value}
            >
              {value === 'encrypt' ? 'Encrypt sensitive input' : 'Decrypt stored ciphertext'}
            </button>
          ))}
        </div>
      </div>

      <form className="form-grid" onSubmit={handleSubmit}>
        <div>
          <label htmlFor="sandboxKey">Key / certificate secret</label>
          <input
            id="sandboxKey"
            name="key"
            value={form.key}
            onChange={handleChange}
            placeholder="Use the same key for encrypt & decrypt"
          />
        </div>

        {mode === 'encrypt' ? (
          <>
            <div>
              <label htmlFor="password">Password column</label>
              <input
                id="password"
                name="password"
                value={form.password}
                onChange={handleChange}
                placeholder="Enter plaintext password"
                required
              />
            </div>
            <div>
              <label htmlFor="card">Credit card column</label>
              <input
                id="card"
                name="card"
                value={form.card}
                onChange={handleChange}
                placeholder="4111 1111 1111 1111"
                required
              />
            </div>
          </>
        ) : (
          <div>
            <label htmlFor="ciphertext">Ciphertext payloads</label>
            <textarea
              id="ciphertext"
              name="password"
              value={form.password}
              onChange={handleChange}
              placeholder="Paste encrypted password"
            ></textarea>
            <textarea
              name="card"
              value={form.card}
              onChange={handleChange}
              placeholder="Paste encrypted credit card"
            ></textarea>
          </div>
        )}

        <button className="action-button" type="submit">
          {mode === 'encrypt' ? 'Generate ciphertext' : 'Reveal plaintext'}
        </button>
      </form>

      {output && (
        <div className="output-panel">
          {output.error ? (
            <p>{output.error}</p>
          ) : (
            <>
              <div>
                <strong>Password:</strong>
                <code>{output.password}</code>
              </div>
              <div>
                <strong>Credit card:</strong>
                <code>{output.card}</code>
              </div>
              <p>{output.note}</p>
            </>
          )}
        </div>
      )}
    </div>
  );
};

const App = () => (
  <main className="app-shell">
    <header className="header">
      <span className="label">Hands-on experiment · Data encryption in databases</span>
      <h1>Protect data at rest with built-in encryption</h1>
      <p>
        Use the interactive lab to mimic database features: enable Transparent Data Encryption, encrypt specific
        columns, and prove that sensitive fields are unreadable without the correct key.
      </p>
    </header>

    <section className="grid two-columns">
      <div className="card">
        <h2>Experiment roadmap</h2>
        <p>Follow each action and observe the impact immediately on the right-hand simulations.</p>
        <StepList />
      </div>
      <TDECard />
    </section>

    <section className="grid">
      <ColumnEncryptionLab />
      <EncryptionSandbox />
    </section>

    <p className="footer-note">
      This lab runs entirely in your browser. React + CryptoJS simulate what the database engine performs in the
      background when you enable encryption.
    </p>
  </main>
);

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
