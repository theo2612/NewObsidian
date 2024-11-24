*Sample Command*
`echo "name:address:DoB" | awk -F: '{print $1}'`
### **AWK Cheat Sheet**

#### **Basics**
- **Structure**: `awk 'pattern {action}' file`
  - `pattern`: Specifies the lines to process (can be regex or condition).
  - `action`: Specifies what to do with matching lines.
  - Default: If no `pattern` is given, all lines are processed. If no `action` is given, it prints the entire line.

#### **Options**
- `-F` : Set the field delimiter (default is whitespace).
  - Example: `awk -F: '{print $1}' file` (uses colon `:` as delimiter).

#### **Special Variables**
- `$0`: Entire current line.
- `$1`, `$2`, ..., `$n`: Fields in the current line (space/tab-separated by default).
- `NR`: Line number.
- `NF`: Number of fields in the current line.
- `FS`: Field separator (default: space/tab; can be changed with `-F` or `BEGIN` block).
- `OFS`: Output field separator (default: space).

#### **Common Actions**
- `print`: Print data.
  - Example: `awk '{print $1, $2}' file` (prints first two fields).
- `printf`: Formatted output (like C’s `printf`).
  - Example: `awk '{printf "%s - %s\n", $1, $2}' file`.

#### **Patterns**
- `/regex/`: Match lines containing the regex.
  - Example: `awk '/error/' file` (prints lines with "error").
- `expression`: Match lines where the expression is true.
  - Example: `awk '$3 > 100' file` (lines where the third field is greater than 100).

#### **Conditionals**
- `if` statements:
  ```awk
  awk '{if ($3 > 100) print $0}' file
  ```
- Inline ternary:
  ```awk
  awk '{print ($3 > 100 ? "High" : "Low")}' file
  ```

#### **Loops**
- `for` loops:
  ```awk
  awk '{for (i=1; i<=NF; i++) print $i}' file
  ```

#### **Useful Built-In Functions**
- **String functions**:
  - `length($0)`: Length of the line.
  - `toupper(str)`: Convert string to uppercase.
  - `tolower(str)`: Convert string to lowercase.
  - `substr(str, start, length)`: Extract substring.
    - Example: `awk '{print substr($0, 1, 10)}' file`.

- **Math functions**:
  - `int(num)`: Convert to integer.
  - `sqrt(num)`: Square root.
  - `rand()`: Random number between 0 and 1.

#### **Blocks**
- **BEGIN**: Runs once before processing the file.
  ```awk
  awk 'BEGIN {print "Start of Processing"} {print $1}' file
  ```
- **END**: Runs once after processing the file.
  ```awk
  awk '{count++} END {print "Total lines:", count}' file
  ```

#### **Examples**
1. **Print specific fields**:
   ```bash
   awk '{print $1, $3}' file
   ```

2. **Change field separator**:
   ```bash
   awk -F, '{print $1, $2}' file
   ```

3. **Count lines**:
   ```bash
   awk 'END {print NR}' file
   ```

4. **Sum values in a column**:
   ```bash
   awk '{sum += $2} END {print sum}' file
   ```

5. **Filter lines**:
   ```bash
   awk '$3 > 50 {print $1, $3}' file
   ```

6. **Highlight matching lines**:
   ```bash
   awk '/ERROR/ {print "Error found:", $0}' file
   ```

7. **Print unique values from a column**:
   ```bash
   awk '!seen[$1]++ {print $1}' file
   ```

#### **AWK One-Liners**
- **Count occurrences of each word**:
  ```bash
  awk '{for (i=1; i<=NF; i++) freq[$i]++} END {for (word in freq) print word, freq[word]}' file
  ```

- **List all unique fields in a column**:
  ```bash
  awk '{print $2}' file | sort | uniq
  ```

- **Replace a string**:
  ```bash
  awk '{gsub("old", "new"); print}' file
  ```

- **Extract lines between patterns**:
  ```bash
  awk '/start/,/end/' file
  ```

#### **Tips**
- Combine with `grep`, `sed`, `sort`, and `uniq` for powerful text processing.
- Use `-v` to pass shell variables to `awk`:
  ```bash
  awk -v var="value" '$1 == var {print $0}' file
  ```

Let me know if you’d like examples tailored to a specific task!