const API_BASE_URL = 'https://stripe-checker-eight.vercel.app';
const API_PATH = '/api/stripe10';

const checkBtn = document.getElementById('check-btn');
const stopCheckBtn = document.getElementById('stop-check-btn');
const numbersTextarea = document.getElementById('numbers');
const resultOutputTextarea = document.getElementById('result-output');
const liveNumbersTextarea = document.getElementById('ali-numbers');
const deadNumbersTextarea = document.getElementById('muhammad-numbers');

let stopChecking = false;
let liveCount = 0;
let deadCount = 0;

checkBtn.addEventListener('click', startChecking);
stopCheckBtn.addEventListener('click', () => {
    stopChecking = true;
    stopCheckBtn.disabled = true;
    checkBtn.disabled = false;
    appendToStatusOutput("⏹️ Checking stopped by user.\n");
});

function toggleButtons() {
    checkBtn.disabled = true;
    stopCheckBtn.disabled = false;
}

async function startChecking() {
    stopChecking = false;
    liveCount = 0;
    deadCount = 0;

    resultOutputTextarea.value = "";
    liveNumbersTextarea.value = "";
    deadNumbersTextarea.value = "";
    updateSummaryCounts(0, 0);

    const input = numbersTextarea.value.trim();
    const cards = input.split("\n").filter(line => line.trim() !== "");

    if (cards.length === 0) {
        Swal.fire({
            icon: 'warning',
            title: 'No cards provided!',
            text: 'Please enter credit card numbers to check.',
            toast: true,
            position: 'top-end',
            timer: 3000,
            showConfirmButton: false
        });
        return;
    }

    const limit = 50;
    if (cards.length > limit) {
        Swal.fire('Limit Exceeded', `You can only check up to ${limit} cards.`, 'error');
        return;
    }

    checkBtn.disabled = true;
    stopCheckBtn.disabled = false;

    appendToStatusOutput(`⏳ Starting check of ${cards.length} cards...\n`);

    for (let i = 0; i < cards.length; i++) {
        if (stopChecking) break;

        const card = cards[i].trim();

        if (i > 0) {
            await countdownTimer(1);
        }

        appendToStatusOutput(`➡️ Checking card ${i + 1} of ${cards.length}: ${card}\n`);

        try {
            const proxy = "";
            let url = `${API_BASE_URL}${API_PATH}?auth=${encodeURIComponent(card)}`;
            if (proxy) url += `&proxy=${encodeURIComponent(proxy)}`;

            const response = await fetch(url);

            if (!response.ok) throw new Error(`API responded with status ${response.status}`);

            const data = await response.json();

            let status = 'Unknown';
            let message = data.message || data.error || 'Unknown error';

            if (data.status === 'success') {
                status = 'Live';
            } else if (data.status === 'declined') {
                status = 'Dead';
            }

            if (status === 'Live') {
                liveCount++;
                liveNumbersTextarea.value += card + "\n";
                appendToStatusOutput(`Result: ✅ Live | ${message}\n`);
            } else if (status === 'Dead') {
                deadCount++;
                deadNumbersTextarea.value += card + "\n";
                appendToStatusOutput(`Result: 🔴 Dead | ${message}\n`);
            } else {
                appendToStatusOutput(`Result: ❓ Unknown | ${message}\n`);
            }
            updateSummaryCounts(liveCount, deadCount);

        } catch (error) {
            appendToStatusOutput(`❌ Error checking card ${card}: ${error.message}\n`);
        }

    }

    if (!stopChecking) {
        appendToStatusOutput("\n✅ Checking Finished!\n");
        checkBtn.disabled = false;
        stopCheckBtn.disabled = true;

        Swal.fire({
            icon: 'success',
            title: 'All cards checked!',
            toast: true,
            position: 'top-end',
            timer: 3000,
            showConfirmButton: false
        });
    }
}

function countdownTimer(seconds) {
    return new Promise(resolve => {
        let timeLeft = seconds;
        const baseValue = resultOutputTextarea.value;
        const updateWaitText = () => {
            if (timeLeft <= 0) {
                resultOutputTextarea.value = baseValue;
                resolve();
            } else {
                resultOutputTextarea.value = baseValue + `⏳ Waiting: ${timeLeft} second(s) left...\n`;
                resultOutputTextarea.scrollTop = resultOutputTextarea.scrollHeight;
                timeLeft--;
                setTimeout(updateWaitText, 1000);
            }
        };
        updateWaitText();
    });
}

function appendToStatusOutput(text) {
    resultOutputTextarea.value += text;
    resultOutputTextarea.scrollTop = resultOutputTextarea.scrollHeight;
}

function updateSummaryCounts(live, dead) {
    document.getElementById('ali-count').textContent = live;
    document.getElementById('muhammad-count').textContent = dead;
}

function copyToClipboard(id) {
    const textarea = document.getElementById(id);
    textarea.select();
    document.execCommand("copy");

    Swal.fire({
        icon: 'success',
        title: 'Copied!',
        toast: true,
        position: 'top-end',
        timer: 1500,
        showConfirmButton: false
    });
}

function toggleMenu() {
    const menu = document.getElementById('dropdown-menu');
    menu.classList.toggle('show');
}

document.addEventListener('click', function (event) {
    const toggle = document.querySelector('.menu-toggle');
    const menu = document.getElementById('dropdown-menu');

    if (!menu.contains(event.target) && !toggle.contains(event.target)) {
        menu.classList.remove('show');
    }
});
