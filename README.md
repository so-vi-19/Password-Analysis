# Password-Analysis
Tool Used for analyzing passwords after a domain dump this tool looks at the following:
- How many accounts were cracked out of the total attempted
- How many cracked passwords contain a campus-name variation (case, leetspeak, and domain/UPN aware)
- How many **sensitive accounts** (admins, finance, etc.) were cracked
- General descriptive statistics about the cracked password set
- Other weak patterns (keyboard walks, season+year, etc


## 1. Requirements
- `python-docx` (only needed if you want the `.docx` report)
-  Python3

## 2. Prepare your input files

### A. The cracked-passwords file (`--cracked`)
This code runs on the idea that you have a Hashcat file that contains the following format: Domain/User:HASH:crackedpass

```
BAU/reid:5f4dcc3b5aa765d61d8327deb882cf99:Quantico2024!
BAU/hotchner:098f6bcd4621d373cade4e832627b4f6:quanticoacademy1
garcia@bau.gov:c4ca4238a0b923820dcc509a6f75849b:qwerty123
```

When we run hashcat originally against the first files you will often get an output like: hash:crackedpass. In order for the analyzer to run you need to create the correct format file. To do this you will need to run:

```
hashcat -D 2 -O -w 4  -d 1,2,3,4 -m 1000 -a 0 --hwmon-temp-abort=100 'Domain_Dump.ntds' -r <ruleset> <wordlist> --show --username -o <output file>
```
Once you have ran this file you will need to separate any of the previous contents in the file that exist to get just the format you need you can run 

```
grep -P '^[^:]*\\' Domain_Dump_Outputfile | tee Domain_user_hash_crackedpass_format
```

Format: `username:hash:password` (or `domain\username:hash:password`, or `username@domain:hash:password`). Use `--has-username` on the command line when your file looks like this.

### B. Campus keywords
 
Give the script your campus name and it derives useful variants (acronym, concatenated name, significant words) automatically:

```
--campus-name "Riverside State University"
```
For anything it can't guess — mascot, city, athletics nickname, old name — add a keywords file, one entry per line:
 
**campus_keywords.txt**
```
anything related to the campus
```
 
You need at least one of `--campus-name` or `--keywords-file`.
 
### C. Sensitive accounts 
 
A plain list of usernames you want tracked separately — admins, service accounts, finance, executives, etc. **Just the username, no domain prefix needed:** 
for this it is recommended that you pull all of the domain admins from either Bloodhound or NXC
```
nxc ldap <DC IP> -u <user> -p <pass> --groups "Domain Admins"
```

## 3. Run it

### Full example (all features)
 
```
python3 analyze_passwords.py  --cracked hashcat_output.txt --has-username --total-count 5000 --campus-name "Quantico Academy"  --keywords-file campus_keywords.txt --sensitive-accounts sensitive_users.txt  --out report.json --csv report.csv --docx report.docx
```
### Minimal example (just campus-name matching)
 
```
python3 analyze_passwords.py --cracked cracked.txt --campus-name "Quantico Academy" --docx report.docx
```

---
 
## 4. What you get
 
| Flag | Output |
|---|---|
| `--out report.json` | Full structured report, everything the script computed |
| `--csv report.csv` | Just the campus-name-matching passwords, for a quick list |
| `--docx report.docx` | Formatted Word document — overview, general stats, campus-name section, sensitive-account section, other patterns |
 
The Word doc includes:
1. **Overview** — accounts attempted, total cracked, crack rate, campus-variant count, sensitive-account summary
2. **General Password Statistics** — unique vs. reused passwords, length distribution, character composition, most common passwords
3. **Campus-Name Variation** — matched keyword frequency and a sample table of matches
4. **Sensitive Account Exposure** — which sensitive accounts were cracked and whether they also used a campus-name variant
5. **Other Weak Patterns** — keyboard walks, season+year combos, repeated characters, etc.
---
