# SecSkills - Security Skills Plugin for Claude Code

> **Transform Claude Code into your personal penetration testing assistant with 16 specialized security skills and 6 expert AI subagents.**

## 🎯 What is This?

**SecSkills** is a plugin for [Claude Code](https://claude.ai/code) that gives Claude deep expertise in offensive security and penetration testing. Instead of generic security advice, you get:

- **Instant access to 16 specialized security skills** covering web apps, cloud, mobile, Active Directory, and more
- **6 AI security experts** (subagents) that automatically handle complex pentesting tasks
- **Ready-to-use commands and payloads** for real-world security testing
- **Intelligent context awareness** - Claude knows when to use which skill

Think of it as having a team of penetration testers available 24/7 through Claude Code.

## 👥 Who Should Use This?

- **Penetration Testers** - Automate reconnaissance, exploit development, and reporting
- **Red Team Operators** - Get instant access to post-exploitation techniques and persistence methods
- **Bug Bounty Hunters** - Quickly test for vulnerabilities across web, mobile, and cloud
- **Security Researchers** - Research new attack vectors with comprehensive tooling knowledge
- **Security Students** - Learn offensive security with practical, command-line examples
- **CTF Players** - Solve challenges faster with instant technique references

**Prerequisites:**
- Access to [Claude Code](https://claude.ai/code)
- Basic understanding of security testing concepts
- Authorization to test the systems you're targeting (ethical hacking only!)

## 🚀 Quick Start (5 Minutes)

### Step 1: Install the Plugin

**Option A: Via Claude Code (Recommended)**
```bash
/plugin marketplace add trilwu/secskills
/plugin install trilwu/secskills
/plugin enable secskills
```

**Option B: Manual Installation**
```bash
git clone https://github.com/trilwu/secskills ~/.claude/plugins/secskills
```

### Step 2: Verify Installation

In Claude Code, type:
```
/plugin list
```
You should see `secskills` in the list of enabled plugins.

### Step 3: Try Your First Security Task

Simply ask Claude in natural language:

**Example 1: Web Application Testing**
```
"How do I test this login form for SQL injection?"
```
→ The web application security skill automatically activates with SQLi techniques

**Example 2: Cloud Security**
```
"I found AWS keys in a GitHub repo. How do I enumerate what they can access?"
```
→ The cloud-pentester subagent activates and provides enumeration commands

**Example 3: Active Directory**
```
"I need to Kerberoast this domain. Walk me through it."
```
→ The pentester subagent provides step-by-step Kerberoasting commands

That's it! Claude now has expert-level security knowledge.

## 📖 How It Works

### Skills (Automatic)
Skills are like reference libraries. When you mention a security topic (like "SQLi", "Kerberos", "Docker escape"), Claude automatically uses the relevant skill to provide accurate commands and techniques.

**16 Skills Available:**
- Web apps, Active Directory, Linux/Windows privilege escalation
- Network services, containers, passwords, APIs
- Mobile (Android/iOS), cloud (AWS/Azure/GCP), wireless
- Phishing, persistence, Web3/smart contracts, reconnaissance

### Subagents (Expert Assistants)
Subagents are specialized AI experts that can handle complex, multi-step security tasks autonomously. They automatically activate based on context or can be explicitly invoked.

**6 Subagents Available:**
- `pentester` - General pentesting (web, AD, infrastructure)
- `cloud-pentester` - AWS, Azure, GCP security
- `mobile-pentester` - Android and iOS app testing
- `web3-auditor` - Smart contract auditing
- `red-team-operator` - Post-exploitation and persistence
- `recon-specialist` - OSINT and reconnaissance

**Automatic Invocation:**
```
"Test this web application" → pentester activates
"Audit this Solidity contract" → web3-auditor activates
"Find subdomains for example.com" → recon-specialist activates
```

**Manual Invocation:**
```
"Use the cloud-pentester to assess my AWS account"
"Have the mobile-pentester analyze this APK"
"Get the recon-specialist to map the attack surface"
```

## 🎓 Learning Examples

### Beginner: SQL Injection Testing
```
You: "I want to test if this endpoint is vulnerable to SQL injection:
     https://example.com/api/users?id=1"

Claude: [Activates web application security skill]
        Here's how to test for SQL injection:

        1. Basic injection test:
           curl "https://example.com/api/users?id=1'"

        2. Boolean-based test:
           curl "https://example.com/api/users?id=1 AND 1=1"

        3. Automated with SQLMap:
           sqlmap -u "https://example.com/api/users?id=1" --batch

        [Provides full testing methodology...]
```

### Intermediate: Cloud Enumeration
```
You: "I have AWS access keys. How do I see what I can access?"

Claude: [Activates cloud-pentester subagent]
        I'll help enumerate AWS permissions. Here's the process:

        1. Verify credentials:
           aws sts get-caller-identity

        2. List permissions (if allowed):
           aws iam get-user
           aws iam list-attached-user-policies

        3. Enumerate resources:
           aws s3 ls
           aws ec2 describe-instances

        [Provides comprehensive enumeration guide...]
```

### Advanced: Full Penetration Test
```
You: "I need to perform a web application penetration test on example.com"

Claude: [Activates pentester subagent]
        I'll guide you through a comprehensive web application pentest:

        Phase 1: Reconnaissance
        [Detailed recon commands...]

        Phase 2: Vulnerability Discovery
        [Testing methodology...]

        Phase 3: Exploitation
        [Exploitation techniques...]

        [Provides full pentest methodology with commands...]
```

## ❓ FAQ

### How do I know if the plugin is working?
Ask Claude a security question like "How do I test for SQL injection?" - if you get detailed commands and techniques, it's working!

### Do I need to install any tools?
No, the plugin only provides knowledge. You'll need to install tools like `nmap`, `sqlmap`, `burpsuite`, etc. separately if you want to run the commands.

### Can I use this for illegal hacking?
**Absolutely not.** This plugin is for authorized security testing only. Always get written permission before testing any system you don't own.

### Which subagent should I use?
- General web/infrastructure → `pentester`
- AWS/Azure/GCP → `cloud-pentester`
- Android/iOS apps → `mobile-pentester`
- Smart contracts → `web3-auditor`
- After compromise (persistence, lateral movement) → `red-team-operator`
- Initial reconnaissance → `recon-specialist`

### How do I update the plugin?
```bash
cd ~/.claude/plugins/secskills
git pull origin main
```

### Can I contribute new skills?
Yes! Fork the repository, add your skill following the format in `skills/`, and submit a pull request.

## 🐛 Troubleshooting

### Plugin not showing in `/plugin list`
```bash
# Check if plugin directory exists
ls ~/.claude/plugins/secskills

# If not, clone it manually
git clone https://github.com/trilwu/secskills ~/.claude/plugins/secskills

# Restart Claude Code
```

### Skills not activating automatically
Try being more specific with security terminology:
- Instead of: "test this website"
- Try: "test this website for SQL injection vulnerabilities"

Or explicitly invoke a subagent:
```
"Use the pentester to test this application"
```

### Commands not working on my system
The plugin provides Linux/Kali-based commands by default. For Windows, you may need to:
- Use WSL (Windows Subsystem for Linux)
- Install tools via Chocolatey or manual installation
- Ask Claude: "How do I run this on Windows?"

## 💡 Common Use Cases

### 1. Bug Bounty Hunting
```
"I'm testing a bug bounty program for example.com. Walk me through the recon phase."
```
→ recon-specialist provides full OSINT methodology

### 2. Web Application Pentest
```
"Test this login endpoint for common vulnerabilities: https://app.example.com/login"
```
→ pentester checks for SQLi, XSS, auth bypass, etc.

### 3. Internal Network Assessment
```
"I have access to 10.10.10.0/24. Help me enumerate and exploit services."
```
→ pentester provides network scanning and exploitation techniques

### 4. Cloud Security Review
```
"I need to audit our AWS infrastructure for misconfigurations."
```
→ cloud-pentester provides AWS security assessment commands

### 5. Mobile App Analysis
```
"Analyze this APK file for security issues: app.apk"
```
→ mobile-pentester walks through static and dynamic analysis

### 6. Smart Contract Audit
```
"Review this Solidity contract for vulnerabilities: [paste code]"
```
→ web3-auditor checks for reentrancy, overflow, access control issues

## 💪 Tips & Best Practices

### Be Specific
❌ "How do I hack this?"
✅ "How do I test this web form for SQL injection vulnerabilities?"

### Provide Context
Tell Claude:
- What phase you're in (recon, exploitation, post-exploit)
- What access you have (unauthenticated, low-priv user, root)
- What you've already tried
- What OS/environment you're working with

### Use Subagents for Complex Tasks
For multi-step tasks, explicitly invoke a subagent:
```
"Use the pentester to perform a full security assessment of this application"
```

### Ask for Explanations
```
"Explain how this Kerberoasting attack works before showing me the commands"
```

### Request Different Approaches
```
"Show me both a manual approach and an automated tool for this"
```

### Chain Commands
```
"First use recon-specialist to map the attack surface, then use pentester to test vulnerabilities"
```

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Adding New Skills
1. Fork the repository
2. Create a new skill directory in `skills/`
3. Follow the YAML frontmatter format (see existing skills)
4. Keep skills under 600 lines
5. Focus on commands/payloads, not explanations
6. Submit a pull request

### Improving Existing Skills
- Add new techniques or commands
- Fix outdated information
- Improve clarity or structure
- Report bugs or issues

### What We're Looking For
- **New attack techniques** from recent research
- **Tool updates** (new versions, new features)
- **Platform-specific variants** (Windows, macOS, mobile)
- **Real-world case studies** and practical examples
- **Bug fixes** and documentation improvements

**Contribution Guidelines:**
- All contributions must be for authorized, ethical security testing
- Include references/sources for techniques
- Test commands before submitting
- Follow existing formatting and style

## ⚖️ Legal Disclaimer

**IMPORTANT: READ BEFORE USE**

This plugin is designed for:
✅ **Authorized penetration testing** with written permission
✅ **Bug bounty programs** within defined scope
✅ **Security research** on owned/controlled systems
✅ **Educational purposes** in lab environments
✅ **CTF competitions** and security challenges
✅ **Defensive security** and threat intelligence

This plugin is **NOT** for:
❌ Unauthorized access to systems
❌ Illegal hacking or computer crime
❌ Violating terms of service
❌ Malicious activities

**You are responsible for:**
- Obtaining proper authorization before testing
- Complying with all applicable laws and regulations
- Using techniques ethically and responsibly
- Understanding the impact of your actions

**The authors and contributors:**
- Provide this software "as is" without warranty
- Are not responsible for misuse or illegal activities
- Do not condone unauthorized security testing
- Assume no liability for damages resulting from use

By using this plugin, you agree to use it only for lawful, authorized purposes.

## 📞 Support & Community

### Getting Help
- **Documentation**: Read this README thoroughly
- **Issues**: Report bugs at [GitHub Issues](https://github.com/trilwu/secskills/issues)
- **Questions**: Use [GitHub Discussions](https://github.com/trilwu/secskills/discussions)

### Stay Updated
- **Star** the repository to show support ⭐
- **Watch** for updates and new releases
- **Fork** to create your own customized version

### Resources
- [Claude Code Documentation](https://docs.claude.com/en/docs/claude-code)
- [HackTricks Wiki](https://github.com/HackTricks-wiki/hacktricks)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [MITRE ATT&CK](https://attack.mitre.org/)

## 📊 Project Information

- **Version**: 1.0.0
- **License**: MIT
- **Primary Source**: HackTricks Security Wiki and offensive security community knowledge
- **Purpose**: Transform security knowledge into actionable Claude agent skills
- **Quality**: Production-ready, following official Claude Code best practices
- **Scope**: Comprehensive security testing coverage (95%+ of modern scenarios)
- **Architecture**: 16 production-ready skills + 6 specialized subagents

---

**Made with ❤️ by the security community for ethical hackers worldwide.**

*Remember: With great power comes great responsibility. Always hack ethically and with authorization.*
