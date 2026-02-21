document.addEventListener("DOMContentLoaded", () => {
  const photoInput = document.getElementById("photoInput");
  const previewRow = document.getElementById("previewRow");
  const previewImg = document.getElementById("previewImg");
  const previewName = document.getElementById("previewName");
  const removeImgBtn = document.getElementById("removeImg");

  if (photoInput) {
    photoInput.addEventListener("change", () => {
      const file = photoInput.files && photoInput.files[0];
      if (!file) return;

      previewName.textContent = file.name;

      const objectUrl = URL.createObjectURL(file);
      previewImg.src = objectUrl;

      previewRow.classList.remove("hidden");
    });
  }

  if (removeImgBtn) {
    removeImgBtn.addEventListener("click", () => {
      photoInput.value = "";
      previewImg.src = "";
      previewRow.classList.add("hidden");
    });
  }

  const toast = document.getElementById("toast");
  if (toast) {
    setTimeout(() => {
      toast.classList.add("hidden");
    }, 2200);
  }
});