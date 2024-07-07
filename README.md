# Kcalio Documentation

##URL
https://kcal-io.onrender.com

## Project Summary
The purpose of Kcalio is to help users lose and track their weight by making it easier to track their caloric input (what you eat) and output (what you burn) to ensure that a caloric deficit is maintained for weight loss. This is done by connecting the user to their Fitbit account and updating their gross caloric burn through the data recieved from Fitbit's API.
 
Tracking food is made easier by allowing the user to upload a photo of their food, which gets passed onto openAI's 4o model, equipt with computer vision, to recognizae the food and estimate the caloric and macronutrient content and logging it into the users account. Alternatively, users can still manually log their caloric intake through an alternate form if they choose to not leave their caloric input data up to estimate.

d3.js is used to visualize the caloric input and output data as well as the user's weight data in order to display trending data to remind users whether or not they're on track to their weight loss goals.

## Tools Used for this application:

### Technology Stack
- HTML
- CSS
- JavaScript
- Python
- Flask

### Database
- PostgreSQL

### APIs
- openAI
- Fitbit

### UI Tools
- d3.js
- Bootstrap
- Jinja
- Flask WTForms

## Database ERD Diagram:
![Kcalio ERD Diagram](/static/images/kcalio%20ERD.jpeg "Kcalio ERD Diagram")

## User FLow Diagram:
![Kcalio User Flow Diagram](static/images/Kcalio%20User%20Flow.jpg "Kcalio User Flow Diagram")