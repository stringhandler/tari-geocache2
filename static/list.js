const BASE_URL = window.ENV?.BASE_URL || '';

let geocaches = [];

// Load geocaches on page load
window.addEventListener('DOMContentLoaded', loadGeocaches);

async function loadGeocaches() {
    const loading = document.getElementById('loading');
    const error = document.getElementById('error');
    const list = document.getElementById('geocacheList');
    const stats = document.getElementById('stats');

    try {
        loading.style.display = 'block';
        error.style.display = 'none';

        const response = await fetch(`${BASE_URL}/api/geocaches`);

        if (!response.ok) {
            throw new Error('Failed to fetch geocaches');
        }

        geocaches = await response.json();
        loading.style.display = 'none';

        if (geocaches.length === 0) {
            list.innerHTML = `
                <div class="empty-state">
                    <h2>No Geocaches Yet</h2>
                    <p>Create your first geocache to get started!</p>
                    <br>
                    <a href="/" class="btn">Create Geocache</a>
                </div>
            `;
        } else {
            // Show stats
            stats.style.display = 'grid';
            document.getElementById('totalCaches').textContent = geocaches.length;

            // Render geocaches
            list.innerHTML = geocaches.map(geocache => renderGeocacheCard(geocache)).join('');
        }
    } catch (err) {
        loading.style.display = 'none';
        error.style.display = 'block';
        error.textContent = `Error: ${err.message}`;
    }
}

function renderGeocacheCard(geocache) {
    const hasCoordinates = geocache.latitude && geocache.longitude;
    const coordinates = hasCoordinates
        ? `${geocache.latitude.toFixed(6)}, ${geocache.longitude.toFixed(6)}`
        : 'No coordinates';

    const description = geocache.description
        ? escapeHtml(geocache.description)
        : '<em>No description</em>';

    const createdDate = geocache.created_at
        ? new Date(geocache.created_at).toLocaleDateString()
        : 'Unknown';

    return `
        <div class="geocache-card" onclick="viewGuestbook('${geocache.short_id}')">
            <div class="geocache-header">
                <div>
                    <div class="geocache-name">${escapeHtml(geocache.name)}</div>
                    <div class="geocache-id">ID: ${geocache.short_id || geocache.id}</div>
                </div>
            </div>

            <div class="geocache-description">${description}</div>

            <div class="geocache-meta">
                <div class="geocache-meta-item">
                    📍 ${coordinates}
                </div>
                <div class="geocache-meta-item">
                    📅 Created ${createdDate}
                </div>
            </div>

            <div class="geocache-actions" onclick="event.stopPropagation()">
                <a href="/?short_code=${geocache.short_id || geocache.id}" class="action-btn">
                    📖 Guestbook
                </a>
                <a href="/admin/${geocache.short_id || geocache.id}" class="action-btn tertiary">
                    🔐 Admin
                </a>
            </div>
        </div>
    `;
}

function viewGuestbook(shortId) {
    window.location.href = `/?short_code=${shortId}`;
}

function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
