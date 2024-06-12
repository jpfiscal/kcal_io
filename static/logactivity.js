document.addEventListener('DOMContentLoaded', function() {
    // Delete activity
    document.querySelectorAll('.delete-activity').forEach(function(button) {
        button.addEventListener('click', function() {
            const activityId = this.getAttribute('data-id');
            if (confirm('Are you sure you want to delete this activity?')) {
                fetch(`/delete_activity/${activityId}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById(`activity-${activityId}`).remove();
                    } else {
                        alert('An error occurred while deleting the activity.');
                    }
                });
            }
        });
    });
});