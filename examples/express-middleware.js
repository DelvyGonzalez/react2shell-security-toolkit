const express = require('express');

function react2ShellProtection(req, res, next) {
  if (req.method !== 'POST') return next();
  
  const suspiciousHeaders = ['next-action', 'rsc-action-id'];
  const hasSuspicious = suspiciousHeaders.some(h => req.headers[h]);
  
  if (hasSuspicious) {
    console.error('[SECURITY] React2Shell attempt blocked:', {
      ip: req.ip,
      path: req.path,
      timestamp: new Date().toISOString()
    });
    return res.status(403).json({ error: 'Request blocked' });
  }
  
  next();
}

module.exports = { react2ShellProtection };
```

---

### ✅ PASO 3: Verificar en VS Code

Deberías ver esta estructura en el panel izquierdo:
```
react2shell-security-toolkit/
├── .github/
│   └── workflows/
│       └── security-check.yml
├── examples/
│   └── express-middleware.js
├── .gitignore
├── cli.js
├── LICENSE
├── package.json
└── README.md