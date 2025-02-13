```markdown
# Secret Scanner

This tool scans your project files for hardcoded credentials, secrets, and sensitive information such as API keys, passwords, tokens, etc. It supports multiple file types like Python, JavaScript, TypeScript, Makefiles, Docker files, Compose files, YAML, and Bash scripts.

## Features
- **Asynchronous file scanning** for better performance.
- **.gitignore integration** to exclude files and folders specified in `.gitignore`.
- Supports **various file formats**: Python, JS, TS, Makefile, Docker, Compose, YAML, Bash.
- **Pattern-based search** for commonly used secret patterns (API keys, passwords, tokens, etc.).
- **Pretty table output** for console results.
- Save results in **JSON** and **CSV** formats.

## Requirements
- Python 3.7+
- `aiofiles` (for async file handling)
- `prettytable` (for displaying results in a table)
- `pytest` and `pytest-asyncio` for testing

You can install the required packages using:

```bash
pip install aiofiles prettytable pytest pytest-asyncio
```

## Usage

### Running the Secret Scanner

1. Clone the repository or copy the script to your project.
2. Run the script in your project root directory. It will scan all files, excluding those in `.gitignore` (if present).

```bash
python secret_scanner.py
```

The script will output found secrets in a table format and save the results to `secrets.json` and `secrets.csv`.

### Configuration

The scanner checks the `.gitignore` file for patterns to exclude from the scan. If no `.gitignore` file is found, it will scan the entire directory.

You can customize the secret detection patterns by modifying the regular expressions in the script. By default, it searches for:

- API keys
- Passwords
- Tokens
- GitHub tokens
- SSH keys
- JWT tokens

### Example Output

Here’s an example of the output when secrets are found:

```
+-------------------------+------------------------+-------+
| Secret                  | File                   | Line  |
+-------------------------+------------------------+-------+
| API_KEY = '123456'      | /path/to/test.py        | 1     |
| password = 'secret'     | /path/to/test.py        | 2     |
+-------------------------+------------------------+-------+
```

### Results Files

The found secrets will be saved in:

- `secrets.json` (in JSON format)
- `secrets.csv` (in CSV format)

### Running Tests

To ensure everything works correctly, you can run the tests using `pytest`:

1. Install `pytest` and `pytest-asyncio`:
   ```bash
   pip install pytest pytest-asyncio
   ```

2. Run the tests:
   ```bash
   pytest test_secret_scanner.py
   ```

## Testing

The code is tested using `pytest` and `pytest-asyncio`. Tests cover the following:

- `.gitignore` parsing
- File exclusion based on `.gitignore`
- Secret detection in various file types (Python, JS, etc.)
- Asynchronous file processing

To run tests:

```bash
pytest
```

## Contributing

Feel free to fork this repository and submit pull requests. All contributions are welcome!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```

### Key Points:
- **Usage Instructions**: How to run the script, configuration options, and output.
- **Testing**: Instructions to run tests, including required dependencies and testing details.
- **Example Output**: A sample of how results will be displayed.
- **Installation**: Steps for setting up the environment and installing dependencies.
