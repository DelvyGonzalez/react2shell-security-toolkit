#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m'
};

const VULNERABLE_VERSIONS = {
  react: ['19.0.0', '19.1.0', '19.1.1', '19.2.0']
};

class React2ShellDetector {
  constructor(projectPath = '.') {
    this.projectPath = path.resolve(projectPath);
    this.packageJsonPath = path.join(this.projectPath, 'package.json');
    this.results = { vulnerable: false, issues: [], recommendations: [] };
  }

  log(message, color = 'reset') {
    console.log(`${colors[color]}${message}${colors.reset}`);
  }

  async scan() {
    this.log('\n============================================================', 'cyan');
    this.log('🔍 React2Shell Security Scan (CVE-2025-55182)', 'bold');
    this.log('============================================================\n', 'cyan');
    this.log(`📁 Scanning project: ${this.projectPath}`, 'cyan');
    this.log(`📅 Scan date: ${new Date().toISOString()}\n`, 'cyan');

    if (!fs.existsSync(this.packageJsonPath)) {
      this.log('❌ Error: package.json not found!', 'red');
      this.log(`   Expected location: ${this.packageJsonPath}\n`, 'yellow');
      process.exit(1);
    }

    try {
      const packageJson = JSON.parse(fs.readFileSync(this.packageJsonPath, 'utf8'));
      
      this.checkReact(packageJson);
      this.checkNextJS(packageJson);
      this.checkServerComponents(packageJson);
      this.generateReport();
      
    } catch (error) {
      this.log(`❌ Error reading package.json: ${error.message}`, 'red');
      process.exit(1);
    }
    
    return this.results;
  }

  checkReact(packageJson) {
    this.log('🔎 Checking React version...', 'cyan');
    const reactDeps = packageJson.dependencies?.react || packageJson.devDependencies?.react;
    
    if (!reactDeps) {
      this.log('   ℹ️  React not found in dependencies\n', 'yellow');
      return;
    }

    const version = reactDeps.replace(/[\^~>=<]/g, '').trim().split(' ')[0];
    this.log(`   Found: React ${version}`, 'reset');

    if (VULNERABLE_VERSIONS.react.includes(version)) {
      this.results.vulnerable = true;
      this.results.issues.push({ 
        package: 'react', 
        currentVersion: version,
        severity: 'CRITICAL'
      });
      this.log(`   ❌ VULNERABLE: React ${version}`, 'red');
      this.log(`   ⚠️  Update to: 19.0.1, 19.1.2, or 19.2.1\n`, 'yellow');
      this.results.recommendations.push({ 
        package: 'react', 
        action: 'npm install react@19.2.1 react-dom@19.2.1' 
      });
    } else {
      this.log(`   ✅ Safe version (${version})\n`, 'green');
    }
  }

  checkNextJS(packageJson) {
    this.log('🔎 Checking Next.js version...', 'cyan');
    const nextDeps = packageJson.dependencies?.next || packageJson.devDependencies?.next;
    
    if (!nextDeps) {
      this.log('   ℹ️  Next.js not found in dependencies\n', 'yellow');
      return;
    }

    const version = nextDeps.replace(/[\^~>=<]/g, '').trim().split(' ')[0];
    this.log(`   Found: Next.js ${version}`, 'reset');

    let isVulnerable = false;
    let recommendedVersion = '';

    if (version.startsWith('15.')) {
      const match = version.match(/^15\.(\d+)\.(\d+)/);
      if (match) {
        const [, minor, patch] = match.map(Number);
        if (minor < 1 || (minor === 1 && patch < 4)) {
          isVulnerable = true;
          recommendedVersion = '15.1.4';
        }
      }
    }
    
    if (version.startsWith('16.')) {
      const match = version.match(/^16\.(\d+)\.(\d+)/);
      if (match) {
        const [, minor, patch] = match.map(Number);
        if (minor === 0 && patch < 7) {
          isVulnerable = true;
          recommendedVersion = '16.0.7';
        }
      }
    }

    if (isVulnerable) {
      this.results.vulnerable = true;
      this.results.issues.push({ 
        package: 'next', 
        currentVersion: version,
        severity: 'CRITICAL'
      });
      this.log(`   ❌ VULNERABLE: Next.js ${version}`, 'red');
      this.log(`   ⚠️  Update immediately!\n`, 'yellow');
      this.results.recommendations.push({ 
        package: 'next', 
        action: `npm install next@${recommendedVersion}`
      });
    } else {
      this.log(`   ✅ Safe version (${version})\n`, 'green');
    }
  }

  checkServerComponents(packageJson) {
    this.log('🔎 Checking for Server Components...', 'cyan');
    const hasServerDom = packageJson.dependencies?.['react-server-dom-webpack'] || 
                        packageJson.devDependencies?.['react-server-dom-webpack'];
    
    if (hasServerDom) {
      this.log('   ⚠️  Found: react-server-dom-webpack', 'yellow');
      this.log('   📋 Review Server Components usage\n', 'yellow');
    } else {
      this.log('   ℹ️  No explicit Server Components packages found\n', 'reset');
    }
  }

  generateReport() {
    this.log('\n============================================================', 'cyan');
    this.log('📊 Security Scan Report', 'bold');
    this.log('============================================================\n', 'cyan');

    if (this.results.vulnerable) {
      this.log('🚨 VULNERABILITY DETECTED: CVE-2025-55182 (React2Shell)', 'red');
      this.log('   Severity: CRITICAL (CVSS 10.0)', 'red');
      this.log('   Status: ACTIVELY EXPLOITED IN THE WILD\n', 'red');
      
      this.log('🔧 Recommended Actions:\n', 'cyan');
      this.results.recommendations.forEach((rec, i) => {
        this.log(`${i + 1}. Update ${rec.package}:`, 'yellow');
        this.log(`   ${rec.action}\n`, 'bold');
      });
      
      this.log('⚡ URGENT: Update immediately!', 'red');
      this.log('   This vulnerability allows remote code execution\n', 'red');
      
      this.log('📚 Resources:', 'cyan');
      this.log('   • https://nvd.nist.gov/vuln/detail/CVE-2025-55182', 'reset');
      this.log('   • https://react.dev/blog/2025/12/03/critical-security-vulnerability', 'reset');
      this.log('\n============================================================\n', 'cyan');
      
      process.exit(1);
    } else {
      this.log('✅ NO KNOWN VULNERABILITIES DETECTED', 'green');
      this.log('   Your dependencies appear to be safe from CVE-2025-55182\n', 'green');
      
      this.log('💡 Best Practices:', 'cyan');
      this.log('   • Keep dependencies updated regularly', 'reset');
      this.log('   • Monitor security advisories', 'reset');
      this.log('   • Use tools like npm audit', 'reset');
      this.log('   • Implement WAF protection\n', 'reset');
      
      this.log('============================================================\n', 'cyan');
      process.exit(0);
    }
  }
}

if (require.main === module) {
  const projectPath = process.argv[2] || '.';
  const detector = new React2ShellDetector(projectPath);
  detector.scan().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

module.exports = React2ShellDetector;