document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scan-form');
    const targetInput = document.getElementById('target-input');
    const startScanBtn = document.getElementById('start-scan-btn');
    const loadingSpinner = document.getElementById('loading-spinner');
    const recentScansTableBody = document.querySelector('#recent-scans-table tbody');
    const toastNotification = document.getElementById('toast-notification');
    let pendingScanIds = [];

    const showToast = (message) => {
        toastNotification.textContent = message;
        toastNotification.classList.remove('hidden');
        setTimeout(() => toastNotification.classList.add('hidden'), 4000);
    };

    const fetchScans = async () => {
        try {
            const res = await fetch('/api/scans');
            const scans = await res.json();
            
            // Check for newly completed scans
            scans.forEach(s => {
                if (s.status === 'Completed' && pendingScanIds.includes(s.id)) {
                    showToast(`Scan for ${s.target} Finished!`);
                    pendingScanIds = pendingScanIds.filter(id => id !== s.id);
                }
            });

            updateTable(scans);
        } catch (err) { console.error(err); }
    };

    const updateTable = (scans) => {
        recentScansTableBody.innerHTML = '';
        scans.forEach(scan => {
            const row = recentScansTableBody.insertRow(-1);
            if (scan.status === 'Pending' && !pendingScanIds.includes(scan.id)) {
                pendingScanIds.push(scan.id);
            }

            const isPending = scan.status === 'Pending';
            row.innerHTML = `
                <td>${scan.target}</td>
                <td>${scan.date}</td>
                <td><span class="status ${scan.status.toLowerCase()}">
                    <i class="fas ${isPending ? 'fa-spinner fa-spin' : 'fa-check-circle'}"></i> ${scan.status}
                </span></td>
                <td>
                    <button class="action-btn" ${isPending ? 'disabled' : ''} 
                        onclick="window.location.href='/results/${scan.id}'">
                        <i class="fas fa-eye"></i> View Results
                    </button>
                </td>
            `;
        });
    };

    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const target = targetInput.value.trim();
        if (!target) return;

        startScanBtn.disabled = true;
        loadingSpinner.classList.remove('hidden');

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target })
            });
            
            if (res.ok) {
                showToast(`Scan started for ${target}`);
                targetInput.value = '';
                fetchScans();
            } else {
                showToast('Error starting scan');
            }
        } catch (err) { showToast('Connection Error'); }
        
        startScanBtn.disabled = false;
        loadingSpinner.classList.add('hidden');
    });

    fetchScans();
    setInterval(fetchScans, 5000);
});
