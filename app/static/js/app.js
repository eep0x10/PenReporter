// ── Sidebar toggle (mobile) ───────────────────────────
function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebarOverlay');
  if (!sidebar) return;
  sidebar.classList.toggle('open');
  overlay.classList.toggle('open');
}

// Auto-dismiss flash alerts after 5s
document.addEventListener('DOMContentLoaded', () => {
  setTimeout(() => {
    document.querySelectorAll('.alert.fade.show').forEach(el => {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(el);
      bsAlert.close();
    });
  }, 5000);

  // Tooltip init
  const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
  tooltips.forEach(el => new bootstrap.Tooltip(el));

  // Highlight active nav on mobile after load
  highlightActiveNav();
});

function highlightActiveNav() {
  const path = window.location.pathname;
  document.querySelectorAll('.nav-item').forEach(item => {
    const href = item.getAttribute('href');
    if (href && path.startsWith(href) && href !== '/') {
      item.classList.add('active');
    }
  });
}

// CVSS Score → Severity helper
function cvssToSeverity(score) {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score > 0)   return 'Low';
  return 'Informational';
}

// Auto-set severity based on CVSS score
const cvssInput = document.querySelector('input[name="cvss_score"]');
const sevSelect = document.querySelector('select[name="severity"]');

if (cvssInput && sevSelect) {
  cvssInput.addEventListener('input', () => {
    const score = parseFloat(cvssInput.value);
    if (!isNaN(score) && score >= 0 && score <= 10) {
      const sev = cvssToSeverity(score);
      sevSelect.value = sev;
      sevSelect.dispatchEvent(new Event('change'));
    }
  });
}

// Confirm delete forms
document.querySelectorAll('form[data-confirm]').forEach(form => {
  form.addEventListener('submit', e => {
    if (!confirm(form.dataset.confirm)) e.preventDefault();
  });
});
