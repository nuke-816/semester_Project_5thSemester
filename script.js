document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scan-form');
    const targetInput = document.getElementById('target-input');
    const startScanBtn = document.getElementById('start-scan-btn');
    const loadingSpinner = document.getElementById('loading-spinner');
    const recentScansTableBody = document.querySelector('#recent-scans-table tbody');
    const toastNotification = document.getElementById('toast-notification');

    // Function to show toast notification
    const showToast = (message) => {
        // Stop any existing animation
        toastNotification.classList.remove('hidden');
        toastNotification.style.animation = 'none';
        toastNotification.offsetHeight; /* trigger reflow */
        toastNotification.style.animation = null; 

        toastNotification.textContent = message;
        
        // Use a timeout to hide it after the animation ends (4s as per CSS)
        clearTimeout(window.toastTimer);
        window.toastTimer = setTimeout(() => {
            toastNotification.classList.add('hidden');
        }, 4000);
    };

    // Function to add a new row to the Recent Scans table
    const addScanRow = (target) => {
        const now = new Date();
        const dateString = now.toISOString().split('T')[0];
        
        const newRow = recentScansTableBody.insertRow(0); // Insert at the top
        
        newRow.innerHTML = `
            <td>${target}</td>
            <td>${dateString}</td>
            <td><span class="status pending"><i class="fas fa-spinner fa-spin"></i> Pending</span></td>
            <td><button class="action-btn view-btn disabled" disabled><i class="fas fa-eye-slash"></i> View Results</button></td>
        `;

        // Simulate scan completion after a delay
        setTimeout(() => {
            newRow.cells[2].innerHTML = `
                <span class="status completed"><i class="fas fa-check-circle"></i> Completed</span>
            `;
            const actionButton = newRow.querySelector('.action-btn');
            actionButton.classList.remove('disabled');
            actionButton.removeAttribute('disabled');
            actionButton.setAttribute('onclick', `window.location.href='results.html?target=${encodeURIComponent(target)}'`);
            actionButton.querySelector('i').className = 'fas fa-eye';
            
            showToast(`Scan for ${target} completed!`);

        }, 5000 + Math.random() * 5000); // 5-10 seconds mock delay
    };

    // Handle form submission
    scanForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const target = targetInput.value.trim();

        if (target) {
            // 1. Disable form and show spinner
            startScanBtn.disabled = true;
            startScanBtn.innerHTML = '<i class="fas fa-cog fa-spin"></i> Scanning...';
            loadingSpinner.classList.remove('hidden');
            targetInput.disabled = true;

            // 2. Simulate API call
            setTimeout(() => {
                // 3. Re-enable form, hide spinner
                startScanBtn.disabled = false;
                startScanBtn.innerHTML = '<i class="fas fa-bolt"></i> Start Scan';
                loadingSpinner.classList.add('hidden');
                targetInput.disabled = false;
                
                // 4. Add the new scan to the table (it starts as 'Pending')
                addScanRow(target);
                
                // 5. Show success notification
                showToast(`Scan for ${target} started!`);

                // 6. Clear input
                targetInput.value = '';

            }, 2000); // 2 seconds to simulate network initiation delay
        }
    });

    // Initial load check for mock data in the table (already added in HTML)
});