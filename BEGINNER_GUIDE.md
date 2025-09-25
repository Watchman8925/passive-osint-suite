# 🎯 ADVANCED OSINT SUITE - COMPLETE BEGINNER'S GUIDE

## **For Complete Beginners - No Technical Experience Required**

Welcome to the most advanced Open Source Intelligence (OSINT) platform available. This guide will walk you through everything step-by-step, assuming you have never used a command line or technical tool before.

---

## 📋 **WHAT YOU'LL NEED (Prerequisites)**

### **1. Computer Requirements**

- **Any modern computer** (Windows, Mac, or Linux)
- **At least 4GB of RAM** (8GB recommended)
- **10GB of free disk space**
- **Internet connection**

### **2. Software to Install First**

**Don't worry - we'll walk through each step!**

#### **A. Python (Programming Language)**

1. Go to: <https://www.python.org/downloads/>
2. Click the big **"Download Python"** button
3. Run the downloaded file
4. **IMPORTANT**: Check the box that says **"Add Python to PATH"**
5. Click **"Install Now"**
6. Wait for installation to complete

#### **B. Node.js (For Web Interface)**

1. Go to: <https://nodejs.org>
2. Click the **"LTS"** version (left button)
3. Run the downloaded file
4. Keep clicking **"Next"** until it installs
5. Restart your computer when done

#### **C. Git (Version Control)**

1. Go to: <https://git-scm.com/downloads>
2. Download for your operating system
3. Install with default settings

---

## 🚀 **STEP 1: GETTING THE SOFTWARE**

### **Windows Users:**

1. Press **Windows Key + R**
2. Type `cmd` and press Enter
3. A black window opens - this is the "Command Prompt"
4. Type exactly: `git clone https://github.com/Watchman8925/passive_osint_suite.git`
5. Press Enter and wait for download

### **Mac Users:**

1. Press **Cmd + Space**
2. Type `Terminal` and press Enter
3. Type exactly: `git clone https://github.com/Watchman8925/passive_osint_suite.git`
4. Press Enter and wait for download

### **Linux Users:**

1. Open Terminal (Ctrl+Alt+T)
2. Type exactly: `git clone https://github.com/Watchman8925/passive_osint_suite.git`
3. Press Enter and wait for download

---

## ⚙️ **STEP 2: SETTING UP THE SOFTWARE**

### **Navigate to the Folder**

In your command prompt/terminal, type:

```bash
cd passive_osint_suite
```

### **Install Python Dependencies**

Type this command and press Enter:

```bash
pip install -r requirements.txt
```

**Wait for this to finish** - it might take 5-10 minutes.

### **Install Additional Dependencies**

Type this command:

```bash
pip install fastapi uvicorn openai transformers torch scikit-learn nltk spacy textblob
```

**Wait for this to finish** - it might take another 10-15 minutes.

---

## 🎯 **STEP 3: YOUR FIRST RUN**

### **Start the Main Program**

In your command prompt/terminal, type:

```bash
python main.py
```

**You should see a colorful menu appear!**

If you see errors, don't panic:

1. Make sure you're in the right folder (`cd passive_osint_suite`)
2. Try: `python3 main.py` instead
3. Make sure Python is installed correctly

---

## 🌐 **STEP 4: ACCESSING THE WEB INTERFACE (EASIEST METHOD)**

### **Starting the Web Portal**

1. From the main menu, type `1` and press Enter
2. The system will automatically:
   - Install web dependencies
   - Start the web server
   - Open your browser
3. **Wait 1-2 minutes** for everything to load
4. Your browser should open to: `http://localhost:3000`

### **If Browser Doesn't Open Automatically**

1. Open any web browser (Chrome, Firefox, Safari, Edge)
2. In the address bar, type: `localhost:3000`
3. Press Enter

**🎉 Congratulations! You now have the web interface running!**

---

## 🔍 **STEP 5: YOUR FIRST INVESTIGATION**

### **Using the Web Interface (Recommended for Beginners)**

#### **1. Cross-Reference Intelligence (Finding Information)**

1. Click on **"Cross-Reference Intelligence"** tile
2. Enter a name, company, or topic you want to research
3. Click **"Start Investigation"**
4. Watch as the system searches:
   - WikiLeaks documents
   - Panama Papers
   - Paradise Papers
   - Pandora Papers
   - Archive.org
   - And 8+ other leak databases
5. Results appear in real-time!

#### **2. Pattern Detection (Finding Hidden Connections)**

1. Click on **"Pattern Detection"** tile
2. Enter multiple pieces of information (one per line):
   - Names
   - Companies
   - Dates
   - Locations
   - Events
3. Click **"Analyze Patterns"**
4. System will find hidden connections you might miss!

#### **3. Conspiracy Theory Validation**

1. Click on **"Conspiracy Analysis"** tile
2. Describe a theory or claim you want to check
3. The system will:
   - Find supporting evidence
   - Find contradicting evidence
   - Calculate probability of truth
   - Show expert analysis
   - Suggest alternative explanations

### **Using the Command Line Interface**

If you prefer the text interface:

#### **From the Main Menu:**

- Type `2` for Cross-Reference Intelligence
- Type `3` for Pattern Detection  
- Type `4` for Conspiracy Analysis
- Type `6` for Email Investigation
- Type `7` for Domain Investigation
- Type `8` for Company Investigation

---

## 📊 **UNDERSTANDING YOUR RESULTS**

### **Cross-Reference Results**

- **Confidence Score**: 0.0-1.0 (higher = more reliable)
- **Relevance Score**: 0.0-1.0 (higher = more related to your search)
- **Source**: Which database found the information
- **Title**: Summary of what was found
- **URL**: Link to original document (if available)

### **Pattern Detection Results**

- **Pattern Type**: Kind of connection found
- **Confidence**: How sure the system is
- **Truth Probability**: Likelihood this is real
- **Significance**: How important this pattern is
- **Evidence**: Supporting information

### **Conspiracy Analysis Results**

- **Truth Probability**: 0-100% chance theory is correct
- **Confidence Level**: How sure the analysis is
- **Evidence Summary**: What supports/contradicts
- **Expert Consensus**: What experts would likely say
- **Alternative Explanations**: Other possible explanations

---

## 🔒 **STAYING SAFE AND ANONYMOUS**

### **Built-in Privacy Protection**

This system automatically:

- **Routes all traffic through Tor** (anonymous browsing)
- **Encrypts all data** you save
- **Processes everything locally** (nothing sent to external AI services)
- **Scrubs metadata** from files
- **Uses anonymous identities** for web requests

### **Additional Safety Tips**

1. **Never investigate yourself** or people you know personally
2. **Use VPN** in addition to built-in Tor
3. **Don't save sensitive results** on cloud storage
4. **Clear browser history** after investigations
5. **Use dedicated computer** for sensitive investigations

---

## 🆘 **TROUBLESHOOTING COMMON PROBLEMS**

### **"Command not found" Error**

- **Problem**: Python or Git not installed correctly
- **Solution**: Reinstall Python/Git and check "Add to PATH"

### **"Permission denied" Error**

- **Windows**: Run Command Prompt as Administrator
- **Mac/Linux**: Add `sudo` before commands (e.g., `sudo pip install...`)

### **"Port already in use" Error**

- **Problem**: Another program using port 3000
- **Solution**: Close the program or restart your computer

### **"Module not found" Error**

- **Problem**: Missing Python dependencies
- **Solution**: Run `pip install -r requirements.txt` again

### **Web interface won't load**

1. Make sure you typed `localhost:3000` correctly
2. Wait 2-3 minutes for server to start
3. Try refreshing the page
4. Check if any firewall is blocking it

### **Slow performance**

1. Close other programs
2. Use fewer search terms
3. Search one database at a time
4. Restart the program

---

## 🎓 **LEARNING MORE**

### **Advanced Features to Try Later**

1. **API Integration**: Add your own API keys for more data sources
2. **Investigation Management**: Create and manage complex cases
3. **Reporting**: Generate professional investigation reports
4. **Automation**: Set up automated monitoring
5. **Custom Patterns**: Define your own analysis patterns

### **Understanding OSINT**

- **OSINT** = Open Source Intelligence
- **Passive** = We don't directly contact targets
- **Cross-Reference** = Finding same information in multiple places
- **Pattern Analysis** = Finding hidden connections
- **Leak Databases** = Collections of exposed/leaked documents

### **Ethical Usage**

✅ **DO Use For:**

- Academic research
- Journalism
- Security research
- Due diligence
- Historical analysis
- Public figure verification

❌ **DON'T Use For:**

- Stalking or harassment
- Personal investigations of private individuals
- Illegal activities
- Corporate espionage
- Privacy violations

---

## 📞 **GETTING HELP**

### **If You Get Stuck**

1. **Read error messages carefully** - they usually tell you what's wrong
2. **Try the web interface** - it's more user-friendly
3. **Restart the program** - fixes many issues
4. **Check your internet connection**
5. **Verify all prerequisites are installed**

### **Common Beginner Mistakes**

1. Not installing Python correctly
2. Running commands in wrong folder
3. Expecting instant results (some searches take time)
4. Not reading the full output
5. Mixing up different search types

---

## 🎯 **QUICK START CHECKLIST**

- [ ] Python installed with "Add to PATH" checked
- [ ] Node.js installed
- [ ] Git installed
- [ ] Downloaded software: `git clone https://github.com/Watchman8925/passive_osint_suite.git`
- [ ] Installed dependencies: `pip install -r requirements.txt`
- [ ] Started program: `python main.py`
- [ ] Accessed web interface: Option 1 from menu
- [ ] Browser opened to `localhost:3000`
- [ ] Performed first investigation
- [ ] Understood results format
- [ ] Saved interesting findings

---

## 🚀 **YOU'RE NOW READY!**

**Congratulations!** You now have access to the most advanced OSINT platform available. You can:

🔍 **Search 12+ leak databases** including WikiLeaks, Panama Papers, and more  
🧠 **Detect hidden patterns** that humans might miss  
📊 **Validate conspiracy theories** with evidence-based analysis  
🔒 **Stay completely anonymous** with built-in privacy protection  
🌐 **Use either web interface or command line** - your choice!  

**Remember**: With great power comes great responsibility. Use these tools ethically and legally.

**Happy investigating! 🕵️‍♂️**

---

*This guide was written for absolute beginners. Even if you've never used a command line before, following these steps carefully will get you up and running with professional-grade intelligence gathering capabilities.*
