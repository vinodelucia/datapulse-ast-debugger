const fs = require('fs');
const { exec } = require('child_process');

// Bug 1: I/O sÃ­ncrono dentro de handler bloqueia o event loop (n/no-sync)
function loadReport(req, res) {
  const data = fs.readFileSync(`./reports/${req.params.id}.json`, 'utf8');
  res.send(data);
}

// Bug 2: Command Injection via exec com template literal (security/detect-child-process)
function archiveFolder(req, res) {
  exec(`tar -czf backup.tgz ${req.query.folder}`, (err, out) => res.send(out));
}

// Bug 3: eval com entrada externa (security/detect-eval-with-expression)
function calculate(req, res) {
  const result = eval(req.body.expression);
  res.json({ result });
}

// Bug 4: SQL Injection via template literal
async function findUser(pool, userId) {
  const { rows } = await pool.query(`SELECT * FROM users WHERE id = '${userId}'`);
  return rows;
}

// Bug 5: Promise sem tratamento de rejeiÃ§Ã£o (promise/catch-or-return)
const syncProfile = (api, id) => {
  api.fetchProfile(id).then((profile) => {
    return profile.name;
  });
};

// Bug 6: Regex vulnerÃ¡vel a ReDoS (security/detect-unsafe-regex)
function isValidSlug(input) {
  return /^(a+)+$/.test(input);
}

// Bug 7: Segredo hardcoded
const connect = () => {
  const apiKey = 'demo-hardcoded-credential-123';
  return { apiKey };
};
