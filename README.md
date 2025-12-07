# 🛡️ React2Shell Security Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CVE-2025-55182](https://img.shields.io/badge/CVE-2025--55182-critical)](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)

**Security toolkit to detect and mitigate CVE-2025-55182 (React2Shell) vulnerability**

> ⚠️ **CRITICAL**: This vulnerability (CVSS 10.0) is being actively exploited!

## Quick Start
```bash
npm install -g react2shell-security-toolkit
npx react2shell-check
```

## What is CVE-2025-55182?

Remote code execution vulnerability affecting:
- ❌ React 19.x Server Components
- ❌ Next.js 15.x / 16.x with App Router
- 💀 CVSS 10.0 (Maximum Severity)

## Remediation

**React:**
```bash
npm install react@19.2.1 react-dom@19.2.1
```

**Next.js 15.x:**
```bash
npm install next@15.1.4
```

**Next.js 16.x:**
```bash
npm install next@16.0.7
```

## About CodersLab

**CodersLab** - Leading nearshore software development company

- 🌐 Website: [coderslab.io](https://coderslab.io)
- 📸 Instagram: [@coderslab.io](https://instagram.com/coderslab.io)
- 👨‍💻 Created by: Delvy González
- 📧 Email: delvy.gonzalez@coderslab.io

## License

MIT License - Copyright (c) 2025 CodersLab

---

Made with ❤️ by CodersLab for the developer community
```

4. Guarda

---

**D) LICENSE**

1. New File → `LICENSE`
2. Pega:
```
MIT License

Copyright (c) 2025 CodersLab - Delvy González

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

**E) .gitignore**

1. New File → `.gitignore`
2. Pega:
```
node_modules/
package-lock.json
*.log
.env
.DS_Store
dist/
build/