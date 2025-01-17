document.addEventListener("DOMContentLoaded", function () {
    // Highlight the active menu item
    document.querySelectorAll('.nav-link').forEach(item => {
      item.addEventListener('click', function () {
        document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));
        this.classList.add('active');
      });
    });
  
    // Smooth scroll to sections
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
      anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
          target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      });
    });
  });
  
// Menampilkan/menghilangkan input RSA ketika mode hybrid diaktifkan
document.getElementById('hybridMode').addEventListener('change', function() {
  const rsaKeyInput = document.getElementById('rsaKeyInput');
  if (this.checked) {
    rsaKeyInput.style.display = 'block';
  } else {
    rsaKeyInput.style.display = 'none';
  }
});

// Validasi form sebelum submit
document.getElementById('encryptionForm').addEventListener('submit', function(event) {
  const fileInput = document.getElementById('file');
  const hybridMode = document.getElementById('hybridMode');
  const rsaKeyInput = document.getElementById('rsaPublicKey');

  if (!fileInput.files.length) {
    event.preventDefault();
    alert('Silakan pilih file untuk dienkripsi.');
    return;
  }

  if (hybridMode.checked && !rsaKeyInput.value.trim()) {
    event.preventDefault();
    alert('Kunci publik RSA harus diisi saat Mode Hybrid diaktifkan.');
    return;
  }
});

function toggleAccordion(button) {
  // Dapatkan konten accordion
  const content = button.nextElementSibling;

  // Toggle konten
  if (content.style.display === "block") {
    content.style.display = "none";
    button.classList.remove("active");
  } else {
    content.style.display = "block";
    button.classList.add("active");
  }
}


function toggleFields() {
  const method = document.getElementById("decrypt_method").value;
  const passwordField = document.getElementById("password_field");
  const privateKeyField = document.getElementById("private_key_field");

  if (method === "Hybrid") {
    passwordField.style.display = "none";
    privateKeyField.style.display = "block";
  } else {
    passwordField.style.display = "block";
    privateKeyField.style.display = "none";
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const flashMessages = document.querySelectorAll('.flash-message');
  flashMessages.forEach(message => {
    setTimeout(() => {
      message.classList.add('fade-out');
      setTimeout(() => {
        message.remove();
      }, 500); // Waktu fade-out
    }, 5000); // Tampilkan selama 5 detik
  });
});

function closePopup() {
  document.querySelector('.flash-message-container').style.display = 'none';
}




