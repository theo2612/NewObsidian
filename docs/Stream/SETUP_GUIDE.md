# Real-Time Caption Translation Setup Guide

This guide will help you set up automatic real-time translation of your voice to Japanese (or any language) in OBS.

## What This Does

- Captures your voice using OBS LocalVocal plugin
- Converts speech to text (English captions)
- Automatically translates to Japanese using ChatGPT
- Displays both original and translated captions on screen

---

## Prerequisites

### 1. Install Python (if not already installed)

1. Download Python from [python.org](https://www.python.org/downloads/)
2. **Important:** During installation, check "Add Python to PATH"
3. Verify installation by opening PowerShell and running:
   ```powershell
   python --version
   ```

### 2. Install OpenAI Python Library

Open PowerShell and run:
```powershell
pip install openai
```

### 3. Get OpenAI API Key

1. Go to [platform.openai.com/api-keys](https://platform.openai.com/api-keys)
2. Sign up or log in
3. Click "Create new secret key"
4. **Copy the key immediately** (you won't be able to see it again)
5. Save it somewhere safe

**Set the API key as an environment variable:**

In PowerShell:
```powershell
$env:OPENAI_API_KEY="YOUR_API_KEY_HERE"
```

**To make it permanent (recommended):**
1. Search Windows for "Environment Variables"
2. Click "Edit the system environment variables"
3. Click "Environment Variables" button
4. Under "User variables", click "New"
5. Variable name: `OPENAI_API_KEY`
6. Variable value: Your API key
7. Click OK

---

## OBS Setup

### 4. Install OBS LocalVocal Plugin

1. Download LocalVocal from [GitHub releases](https://github.com/occ-ai/obs-localvocal/releases)
2. Run the installer
3. Restart OBS if it was open

### 5. Configure LocalVocal in OBS

1. **Add LocalVocal filter to your microphone:**
   - In OBS, go to your Audio Mixer
   - Click the gear icon ⚙️ next to your microphone
   - Select "Filters"
   - Click the "+" button and add "LocalVocal"

2. **Configure LocalVocal settings:**
   - Choose your preferred speech recognition model
   - Enable "Output to file"
   - Set file path to: `C:\Users\YOUR_USERNAME\Desktop\obsoutput.txt`
   - (Replace YOUR_USERNAME with your actual Windows username)

3. **Add text source for original captions (optional):**
   - In OBS, add a new "Text (GDI+)" source
   - Name it "Live Captions"
   - Check "Read from file"
   - Select `obsoutput.txt`
   - Check "Chatlog mode" (shows only latest line)
   - Style it as you like (font, color, size)

4. **Add text source for translated captions:**
   - Add another "Text (GDI+)" source
   - Name it "Translated Captions"
   - Check "Read from file"
   - Select `obstranslated.txt` (will be created automatically)
   - Check "Chatlog mode"
   - Style it differently so you can tell them apart

---

## Translation Script Setup

### 6. Download the Translation Script

Save the `translate_captions.py` file to your Desktop.

### 7. Configure the Script (Optional)

Open `translate_captions.py` in a text editor and adjust if needed:

```python
# File locations
CAPTIONS_FILE = r"C:\Users\YOUR_USERNAME\Desktop\obsoutput.txt"
OUTPUT_FILE   = r"C:\Users\YOUR_USERNAME\Desktop\obstranslated.txt"

# Change target language if desired
TARGET_LANG   = "Japanese"  # Try: "Spanish", "French", "German", etc.

# Timing settings
POLL_SECONDS = 0.20  # How often to check for new captions
MIN_SECONDS_BETWEEN_CALLS = 0.8  # Delay between API calls (to save costs)
```

---

## Running the System

### 8. Start Everything

**Every time you want to use the translation:**

1. **Start OBS** and make sure LocalVocal is enabled on your mic
2. **Open PowerShell** and navigate to your Desktop:
   ```powershell
   cd Desktop
   ```
3. **Run the translation script:**
   ```powershell
   python translate_captions.py
   ```
4. **You should see:**
   ```
   ChatGPT subtitle translator running.
   IN : C:\Users\...\obsoutput.txt
   OUT: C:\Users\...\obstranslated.txt
   Lang: Japanese
   Polling every 0.2s, throttle: 0.8s
   ```

5. **Start speaking!** You should see:
   - `[TRANSLATING] Your speech here`
   - `[SUCCESS] 翻訳されたテキスト`
   - Translations appear in OBS on your stream/recording

### 9. To Stop

Press `Ctrl+C` in PowerShell to stop the translation script.

---

## Troubleshooting

### "OPENAI_API_KEY environment variable not set"
- Make sure you set the environment variable (see step 3)
- If you set it permanently, restart PowerShell
- If you set it in the current session, make sure you're in the same PowerShell window

### "No module named 'openai'"
- Run: `pip install openai`
- Make sure you're using the same Python that has the module installed

### Script runs but no translations appear
- Check that OBS LocalVocal is writing to `obsoutput.txt`
- Speak for at least 5-6 words to trigger translation
- Check the console for `[SKIP] Incomplete` messages
- Make sure your microphone is active in OBS

### Translations are too slow
- Reduce `MIN_SECONDS_BETWEEN_CALLS` (but this increases API costs)
- Use a faster model (though gpt-4o-mini is already fast and cheap)

### OBS text source shows old translations
- Make sure "Chatlog mode" is enabled in the text source settings
- The script overwrites the file each time, so only the latest should show

### LocalVocal file access errors
- The script now handles file locking automatically
- If you still have issues, make sure only one program is writing to the file

---

## Cost Estimates

Using **gpt-4o-mini** for translation:
- Very cheap: ~$0.15 per million input tokens, ~$0.60 per million output tokens
- For a 1-hour stream with moderate talking: **less than $0.10**
- Monitor your usage at [platform.openai.com/usage](https://platform.openai.com/usage)

---

## Customization Ideas

### Change Target Language
Edit `TARGET_LANG` in the script to any language:
- "Spanish", "French", "German", "Korean", "Chinese", etc.

### Adjust Translation Quality
The script uses `gpt-4o-mini` for speed and cost. For better quality:
```python
model="gpt-4o"  # More expensive but higher quality
```

### Change Timing
- **Faster response:** Reduce `MIN_SECONDS_BETWEEN_CALLS` to `0.3`
- **Lower cost:** Increase to `1.5` or higher
- **Check more frequently:** Reduce `POLL_SECONDS` to `0.1`

### Multi-line Translations
The script currently shows only the latest caption. To keep a history, modify the `write_file` function to append instead of overwrite.

---

## Support

If you run into issues:
1. Check the console output for error messages
2. Verify your API key is valid
3. Make sure LocalVocal is outputting to the correct file
4. Check file permissions on the Desktop folder

**Enjoy your real-time translations! 🎉**
