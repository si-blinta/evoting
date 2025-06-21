from flask import Flask, render_template_string, jsonify
from flask_socketio import SocketIO
import threading
import time
from .data import candidates, voters, eligibility_requests, commits, reveals
from .state import ServerState

server_state = ServerState()
app = Flask(__name__)
socketio = SocketIO(app, async_mode='eventlet')


TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>Evoting Bulletin Board</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.1/socket.io.min.js"></script>
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6fa; margin: 0; }
h1 { background: #2d5be3; color: #fff; margin: 0; padding: 24px 0; text-align: center; }
#board { max-width: 950px; margin: 32px auto; display: flex; flex-wrap: wrap; gap: 24px; justify-content: center; }
.card { background: #fff; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.07); padding: 24px; min-width: 260px; max-width: 400px; flex: 1 1 300px; }
.card h2 { margin-top: 0; color: #2d5be3; font-size: 1.2em; border-bottom: 1px solid #e3e7ef; padding-bottom: 8px; }
.json-list { font-family: 'Fira Mono', monospace; background: #f4f6fa; padding: 8px; border-radius: 6px; font-size: 0.95em; overflow-x: auto; }

/* Styles for Commits */
.commit-list, .reveal-list { margin: 0; padding: 0; list-style: none; }
.commit-card, .reveal-card { background: #f8fafd; border-radius: 8px; margin-bottom: 12px; box-shadow: 0 1px 4px #0001; }
.commit-header, .reveal-header { cursor: pointer; padding: 10px 16px; font-weight: bold; color: #2d5be3; border-bottom: 1px solid #e3e7ef; display: flex; align-items: center; justify-content: space-between; }
.commit-fields, .reveal-fields { display: none; padding: 12px 16px; }
.commit-fields.active, .reveal-fields.active { display: block; }

.field-label { font-weight: bold; color: #555; }
.field-value { font-family: 'Fira Mono', monospace; background: #fff; border-radius: 3px; padding: 2px 6px; margin-left: 4px; }
.copy-btn { margin-left: 8px; cursor: pointer; background: #e3e7ef; border: none; border-radius: 3px; padding: 2px 6px; font-size: 0.9em; }
@media (max-width: 900px) { #board { flex-direction: column; align-items: center; } .card { max-width: 95vw; } }
</style>
</head>
<body>
<h1>Evoting Bulletin Board</h1>
<div id="state-timer" style="text-align:center;font-size:1.3em;margin:18px 0 0 0;"></div>
<div id="board"></div>
<script>
// Utility: copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text);
}

// Format long hex: show first 8, ..., last 8
function formatHex(str) {
    if (str.length > 24) return str.slice(0, 8) + "..." + str.slice(-8);
    return str;
}

// Store the expanded state of commit and reveal cards
let expandedCommits = new Set();
let expandedReveals = new Set(); // New Set for reveals

function renderCommits(commits) {
    if (!Array.isArray(commits) || commits.length === 0)
        return "<div class='json-list'>No commits</div>";

    // Field labels for commits based on: pubkey|signedpubkey|seq|signedseq|commithash|signedcommithash
    const commitLabels = [
        "PubKey (hex)", "SignedPubKey (hex)", "Sequence (hex)", "SignedSequence (hex)",
        "CommitHash (hex)", "SignedCommitHash (hex)"
    ];

    let html = "<ul class='commit-list'>";
    commits.forEach((commit, idx) => {
        const fields = commit.split('|').slice(1); // Remove "C|" prefix
        const commitId = commit; // Use full packet as ID

        const isActive = expandedCommits.has(commitId) ? 'active' : '';

        html += `<li class='commit-card'>
            <div class='commit-header' data-commit-id="${commitId}">
                Commit #${idx + 1} <span style="font-size:0.9em;color:#999;">(click to expand)</span>
            </div>
            <div class='commit-fields ${isActive}'>
                ${fields.map((val, i) => `
                    <div>
                        <span class='field-label'>${commitLabels[i] || "Field " + (i + 1)}:</span>
                        <span class='field-value'>${formatHex(val)}</span>
                        <button class='copy-btn' onclick="event.stopPropagation();copyToClipboard('${val.replace(/'/g, "\\'")}')">Copy</button>
                    </div>
                `).join('')}
            </div>
        </li>`;
    });
    html += "</ul>";
    return html;
}

// New function to render reveals
function renderReveals(reveals) {
    if (!Array.isArray(reveals) || reveals.length === 0)
        return "<div class='json-list'>No reveals</div>";

    // Field labels for reveals based on: pubkey|signedpubkey|candidate|salt|signed(candidate+salt)
    const revealLabels = [
        "PubKey (hex)", "SignedPubKey (hex)", "Candidate (hex)", "Salt (hex)", "SignedVote (hex)"
    ];

    let html = "<ul class='reveal-list'>";
    reveals.forEach((reveal, idx) => {
        const fields = reveal.split('|').slice(1); // Remove "R|" prefix
        const revealId = reveal; // Use full packet as ID

        const isActive = expandedReveals.has(revealId) ? 'active' : '';

        html += `<li class='reveal-card'>
            <div class='reveal-header' data-reveal-id="${revealId}">
                Reveal #${idx + 1} <span style="font-size:0.9em;color:#999;">(click to expand)</span>
            </div>
            <div class='reveal-fields ${isActive}'>
                ${fields.map((val, i) => `
                    <div>
                        <span class='field-label'>${revealLabels[i] || "Field " + (i + 1)}:</span>
                        <span class='field-value'>${formatHex(val)}</span>
                        <button class='copy-btn' onclick="event.stopPropagation();copyToClipboard('${val.replace(/'/g, "\\'")}')">Copy</button>
                    </div>
                `).join('')}
            </div>
        </li>`;
    });
    html += "</ul>";
    return html;
}

let timerInterval = null;
let lastTimeLeft = 0;
let lastState = "";

function startCountdown(state, timeLeft) {
    lastTimeLeft = timeLeft;
    lastState = state;
    function updateTimer() {
        let mins = Math.floor(lastTimeLeft / 60);
        let secs = lastTimeLeft % 60;
        let stateLabel = {
            "ELLIGIBILITY": "Eligibility",
            "COMMIT": "Commit",
            "REVEAL": "Reveal",
            "ENDED": "Ended"
        }[lastState] || lastState;
        let timerText = lastState === "ENDED"
            ? `<span style="color:#c00;font-weight:bold;">Voting session ended</span>`
            : `<span style="color:#2d5be3;font-weight:bold;">${stateLabel} state</span> &mdash; <span style="color:#222;">Time left: ${mins}:${secs.toString().padStart(2, "0")}</span>`;
        document.getElementById("state-timer").innerHTML = timerText;
        if (lastTimeLeft > 0 && lastState !== "ENDED") lastTimeLeft--;
    }
    if (timerInterval) clearInterval(timerInterval);
    updateTimer();
    timerInterval = setInterval(updateTimer, 1000);
}

function renderBoard(data) {
    // Countdown 
    if (typeof data.state !== "undefined" && typeof data.time_left !== "undefined") {
        startCountdown(data.state, data.time_left);
        }
    // Capture current expanded states before re-rendering
    expandedCommits.clear();
    document.querySelectorAll('.commit-card .commit-fields.active').forEach(fieldDiv => {
        const headerDiv = fieldDiv.previousElementSibling;
        if (headerDiv && headerDiv.dataset.commitId) {
            expandedCommits.add(headerDiv.dataset.commitId);
        }
    });

    expandedReveals.clear(); // Clear for reveals
    document.querySelectorAll('.reveal-card .reveal-fields.active').forEach(fieldDiv => { // For reveals
        const headerDiv = fieldDiv.previousElementSibling;
        if (headerDiv && headerDiv.dataset.revealId) {
            expandedReveals.add(headerDiv.dataset.revealId);
        }
    });


    let html = "";

    // Candidates
    html += "<div class='card'><h2>Candidates</h2>";
    if (Array.isArray(data.candidates) && data.candidates.length > 0) {
        let cols = Object.keys(data.candidates[0]);
        html += "<table><tr>" + cols.map(col => "<th>" + col + "</th>").join("") + "</tr>";
        html += data.candidates.map(row => "<tr>" + cols.map(col => "<td>" + row[col] + "</td>").join("") + "</tr>").join("");
        html += "</table>";
    } else {
        html += "<div class='json-list'>No candidates</div>";
    }
    html += "</div>";

    // Voters
    html += "<div class='card'><h2>Voters</h2>";
    if (Array.isArray(data.voters) && data.voters.length > 0) {
        let cols = Object.keys(data.voters[0]);
        html += "<table><tr>" + cols.map(col => "<th>" + col + "</th>").join("") + "</tr>";
        html += data.voters.map(row => "<tr>" + cols.map(col => "<td>" + row[col] + "</td>").join("") + "</tr>").join("");
        html += "</table>";
    } else {
        html += "<div class='json-list'>No voters</div>";
    }
    html += "</div>";

    // Eligibility Requests
    html += "<div class='card'><h2>Eligibility Requests</h2>";
    if (Array.isArray(data.eligibility_requests) && data.eligibility_requests.length > 0) {
        let cols = Object.keys(data.eligibility_requests[0]);
        html += "<table><tr>" + cols.map(col => "<th>" + col + "</th>").join("") + "</tr>";
        html += data.eligibility_requests.map(row => "<tr>" + cols.map(col => "<td>" + row[col] + "</td>").join("") + "</tr>").join("");
        html += "</table>";
    } else {
        html += "<div class='json-list'>No eligibility requests</div>";
    }
    html += "</div>";

    // Commits (special rendering)
    html += "<div class='card'><h2>Commits</h2>";
    html += renderCommits(data.commits);
    html += "</div>";

    // Reveals (now with special rendering)
    html += "<div class='card'><h2>Reveals</h2>";
    html += renderReveals(data.reveals); // Use the new renderReveals function
    html += "</div>";

    document.getElementById("board").innerHTML = html;

    // 2. Re-attach event listeners for commit headers after re-rendering
    document.querySelectorAll('.commit-card .commit-header').forEach(header => {
        header.onclick = function() {
            const commitId = this.dataset.commitId;
            const fieldsDiv = this.nextElementSibling;
            fieldsDiv.classList.toggle('active');

            // Update the expandedCommits set
            if (fieldsDiv.classList.contains('active')) {
                expandedCommits.add(commitId);
            } else {
                expandedCommits.delete(commitId);
            }
        };
    });

    // Re-attach event listeners for reveal headers after re-rendering
    document.querySelectorAll('.reveal-card .reveal-header').forEach(header => {
        header.onclick = function() {
            const revealId = this.dataset.revealId; // Get reveal ID
            const fieldsDiv = this.nextElementSibling;
            fieldsDiv.classList.toggle('active');

            // Update the expandedReveals set
            if (fieldsDiv.classList.contains('active')) {
                expandedReveals.add(revealId);
            } else {
                expandedReveals.delete(revealId);
            }
        };
    });
}

var socket = io();
socket.on('update', function(data) { renderBoard(data); });
fetch('/api/board').then(r => r.json()).then(renderBoard);
</script>
</body>
</html>
"""
@app.route("/")
def index():
    return render_template_string(TEMPLATE)

@app.route("/api/board")
def api_board():
    return jsonify({
        "candidates": candidates,
        "voters": voters,
        "eligibility_requests": eligibility_requests,
        "commits": commits,
        "reveals": reveals,
        "state": server_state.get_state(),
        "time_left": int(server_state.get_state_time_left()),
    })

def broadcast_board():
    socketio.emit('update', {
        "candidates": candidates,
        "voters": voters,
        "eligibility_requests": eligibility_requests,
        "commits": commits,
        "reveals": reveals,
        "state": server_state.get_state(),
        "time_left": int(server_state.get_state_time_left()),
    })


def periodic_broadcast():
    while True:
        broadcast_board()
        time.sleep(1)  