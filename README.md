# CommRevote

## Installation

Clone the repository and set up a virtual environment:

```bash
git clone https://github.com/si-blinta/evoting.git
cd evoting/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running

### Start the Server

```bash
python3 -m server.main
```

### Run the Simulation

```bash
# Eligibility phase:
test/eligibility.sh

# Commit phase:
test/commit.sh

# Reveal phase:
test/reveal.sh
```

### Common Commands

```bash
# Initialize a wallet:
python3 -m client.tools.votemanager <wallet> init --passphrase <passphrase>

# Send eligibility request to the server:
python3 -m client.main <wallet> eligibility --id <id>

# Load a commit into a wallet:
python3 -m client.tools.votemanager <wallet> commit --candidate <candidate> --passphrase <passphrase>

# Send commit request to the server:
python3 -m client.main <wallet> commit

# Send reveal to the server:
python3 -m client.main <wallet> reveal

# Do the tallying locally 

python3 -m client.tools.votemanager count --server-url http://localhost:5000

# You can use interactive mode by not using the -- flags

```

## Configuration

- Candidates and voter IDs are defined in `server/data.py`.
- To adjust phase durations, edit `server/state.py`.
- For debugging, set the logger level from `INFO` to `DEBUG` to view packet details.