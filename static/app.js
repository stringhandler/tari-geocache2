const BASE_URL = window.ENV?.BASE_URL || '';

const form = document.getElementById('geocacheForm');
const messageDiv = document.getElementById('message');

// Check for short_code query parameter
const urlParams = new URLSearchParams(window.location.search);
const shortCode = urlParams.get('short_code');

if (shortCode) {
    // Show guestbook view
    document.getElementById('createContainer').style.display = 'none';
    document.getElementById('guestbookContainer').style.display = 'block';
    loadGuestbook(shortCode);
}

function showMessage(text, type) {
    messageDiv.textContent = text;
    messageDiv.className = `message ${type}`;
    messageDiv.style.display = 'block';

    setTimeout(() => {
        messageDiv.style.display = 'none';
    }, 5000);
}

form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = {
        name: document.getElementById('name').value,
        description: document.getElementById('description').value || null,
        latitude: document.getElementById('latitude').value ? parseFloat(document.getElementById('latitude').value) : null,
        longitude: document.getElementById('longitude').value ? parseFloat(document.getElementById('longitude').value) : null,
        view_key: document.getElementById('view_key').value,
        spend_pub_key: document.getElementById('spend_pub_key').value,
    };

    try {
        const response = await fetch(`${BASE_URL}/api/geocaches`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData),
        });

        if (response.ok) {
            const data = await response.json();
            showMessage(`Geocache "${formData.name}" created successfully! ID: ${data.id}`, 'success');
            form.reset();
        } else {
            const error = await response.text();
            showMessage(`Failed to create geocache: ${error}`, 'error');
        }
    } catch (error) {
        showMessage(`Error: ${error.message}`, 'error');
    }
});

// Guestbook functionality
let currentPage = 1;

async function loadGuestbook(shortId, page = 1) {
    try {
        const response = await fetch(`${BASE_URL}/api/guestbook/${shortId}?page=${page}&per_page=20`);

        if (!response.ok) {
            throw new Error('Failed to load guestbook');
        }

        const data = await response.json();
        currentPage = page;

        // Update title
        document.getElementById('guestbookTitle').textContent = `Guestbook - ${shortId}`;
        document.getElementById('guestbookSubtitle').textContent = `${data.total} entries`;

        // Render entries
        const entriesContainer = document.getElementById('guestbookEntries');
        if (data.entries.length === 0) {
            entriesContainer.innerHTML = '<p style="text-align: center; color: #666;">No guestbook entries yet.</p>';
        } else {
            entriesContainer.innerHTML = data.entries.map(entry => `
                <div class="guestbook-entry">
                    <div class="guestbook-entry-header">
                        <div class="guestbook-from">From: ${escapeHtml(entry.from_address)}</div>
                        <div class="guestbook-date">${formatDate(entry.effective_date_time)}</div>
                    </div>
                    <div class="guestbook-memo">${escapeHtml(entry.full_memo)}</div>
                    ${entry.memo_string ? `<div style="font-size: 13px; color: #555; margin-bottom: 8px;">Memo: ${escapeHtml(entry.memo_string)}</div>` : ''}
                    <div class="guestbook-hash">Output: ${escapeHtml(entry.output_hash)}</div>
                </div>
            `).join('');
        }

        // Render pagination
        renderPagination(data, shortId);
    } catch (error) {
        document.getElementById('guestbookEntries').innerHTML =
            `<p style="text-align: center; color: #e53e3e;">Error loading guestbook: ${error.message}</p>`;
    }
}

function renderPagination(data, shortId) {
    const paginationContainer = document.getElementById('pagination');

    if (data.total_pages <= 1) {
        paginationContainer.innerHTML = '';
        return;
    }

    paginationContainer.innerHTML = `
        <button class="pagination-btn" ${data.page === 1 ? 'disabled' : ''} onclick="loadGuestbook('${shortId}', ${data.page - 1})">
            Previous
        </button>
        <div class="pagination-info">
            Page ${data.page} of ${data.total_pages}
        </div>
        <button class="pagination-btn" ${data.page === data.total_pages ? 'disabled' : ''} onclick="loadGuestbook('${shortId}', ${data.page + 1})">
            Next
        </button>
    `;
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

async function scanGeocache() {
    if (!shortCode) {
        alert('No short code available');
        return;
    }

    try {
        const response = await fetch(`${BASE_URL}/api/scan/${shortCode}`);

        if (!response.ok) {
            throw new Error('Failed to scan geocache');
        }

        const data = await response.json();

        // Display scan result
        document.getElementById('scanData').textContent = JSON.stringify(data, null, 2);
        document.getElementById('scanResult').style.display = 'block';

        // Scroll to result
        document.getElementById('scanResult').scrollIntoView({ behavior: 'smooth' });
    } catch (error) {
        alert(`Error scanning geocache: ${error.message}`);
    }
}

function goToAdmin() {
    if (!shortCode) {
        alert('No short code available');
        return;
    }

    // Navigate to admin page
    window.location.href = `${BASE_URL}/admin/${shortCode}`;
}
