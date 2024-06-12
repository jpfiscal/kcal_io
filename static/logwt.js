document.addEventListener('DOMContentLoaded', function() {
    // Delete weight
    document.querySelectorAll('.delete-wt').forEach(function(button) {
        button.addEventListener('click', function() {
            const wtId = this.getAttribute('data-id');
            if (confirm('Are you sure you want to delete this weight data?')) {
                fetch(`/delete_wt/${wtId}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById(`wt-${wtId}`).remove();
                    } else {
                        alert('An error occurred while deleting weight data.');
                    }
                });
            }
        });
    });
});