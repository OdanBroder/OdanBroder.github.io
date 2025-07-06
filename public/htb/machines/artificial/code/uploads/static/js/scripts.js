document.getElementById('model-upload-form').addEventListener('submit', function(event) {
    event.preventDefault();
    const formData = new FormData();
    const fileInput = document.getElementById('model_file');
    formData.append('model_file', fileInput.files[0]);

    fetch('/upload_model', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            alert('Model uploaded successfully!');
        } else {
            alert('Error: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Error uploading model:', error);
    });
});

document.getElementById('review-form').addEventListener('submit', function(event) {
});

document.getElementById('upload-form').addEventListener('submit', function (event) {
    if (document.querySelector('input[type="file"]').files.length === 0) {
        alert("Please select a model file.");
        event.preventDefault();
    }
});

