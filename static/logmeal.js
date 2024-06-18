document.addEventListener('DOMContentLoaded', function() {
    // Delete meal
    document.querySelectorAll('.delete-meal').forEach(function(button) {
        button.addEventListener('click', function() {
            const mealId = this.getAttribute('data-id');
            if (confirm('Are you sure you want to delete this meal?')) {
                fetch(`/delete_meal/${mealId}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById(`meal-${mealId}`).remove();
                    } else {
                        alert('An error occurred while deleting the meal.');
                    }
                });
            }
        });
    });
    
    const spinner = document.getElementById('spinner');

    const showSpinner = () => {
        spinner.style.display = 'block';
    };

    const hideSpinner = () => {
        spinner.style.display = 'none';
    };

    const forms = document.querySelectorAll('form');

    forms.forEach(form => {
        form.addEventListener('submit', function () {
            showSpinner();
        });
    });
});

