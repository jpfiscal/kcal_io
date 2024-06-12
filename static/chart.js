// get data from flask endpoint
//d3.json("/wtHistoryData").then(data =>

function createWtHistoryGraph(data, containerId) {
    const width = 800;
    const height = 400;
    const margin = { top: 50, right: 20, bottom: 50, left: 60 };

    const parseTime = d3.timeParse("%Y-%m-%d");
    
    
    
    data.forEach(d => {
        d.wt_dt = parseTime(d.wt_dt);
        d.wt = +d.wt;
    })

    //Set ranges
    const x = d3.scaleTime().range([0, width - margin.left - margin.right]);
    const y = d3.scaleLinear().range([height - margin.top - margin.bottom, 0]);

    //define the line
    const valueline = d3.line()
        .x(d => x(d.wt_dt))
        .y(d=>y(d.wt));

    //Append the svg object to body of the page
    const svg = d3.select(`#${containerId}`)
        .append("svg")
        .attr("width", width + margin.left + margin.right)
        .attr("height", height + margin.top + margin.bottom)
        .append("g")
        .attr("transform", `translate(${margin.left},${margin.top})`);

    //Add the title
    svg.append("text")
        .attr("x", (width - margin.left - margin.right) / 2)
        .attr("y", -margin.top / 2)
        .attr("text-anchor", "middle")
        .style("font-size", "16px")
        .style("text-decoration", "underline")
        .text("Your Weight History");
    
    //scale the range of data
    x.domain(d3.extent(data, d=> d.wt_dt));
    y.domain([0, d3.max(data, d => d.wt)]);

    //Add horizontal gridlines
    svg.append("g")
        .attr("class", "grid")
        .call(d3.axisLeft(y)
            .tickSize(-width + margin.left + margin.right)
            .tickFormat("")
        );

    //Add valueline path
    svg.append("path")
        .data([data])
        .attr("class", "line")
        .attr("d", valueline)
        .attr("fill", "none")
        .attr("stroke", "blue")
        .attr("stroke-width", 2);

    //Add x-axis
    svg.append("g")
        .attr("transform", `translate(0,${height - margin.top - margin.bottom})`)
        .call(d3.axisBottom(x).tickFormat(d3.timeFormat("%b %d")))
        .selectAll("text")
        .attr("transform", "rotate(-45)")
        .style("text-anchor", "end");

    // Add the y-axis
    svg.append("g")
        .call(d3.axisLeft(y).ticks(10).tickFormat(d=> `${d} kg`));

    // Add axis labels
    svg.append("text")
        .attr("transform", `translate(${(width - margin.left - margin.right) / 2},${height - margin.bottom + 40})`)
        .style("text-anchor", "middle")
        .text("Date");

    svg.append("text")
    .attr("transform", "rotate(-90)")
    .attr("y", 0 - margin.left)
    .attr("x", 0 - (height / 2))
    .attr("dy", "1em")
    .style("text-anchor", "middle")
    .text("Weight (kg)");
}

function createKcalGraph(data, containerId){
    const width = 800;
    const height = 400;
    const margin = { top: 50, right: 20, bottom: 50, left: 80 };

    const parseTime = d3.timeParse("%Y-%m-%d");

    data.forEach(d=> {
        d.date = parseTime(d.date);
        d.kcal_in = +d.kcal_in;
        d.kcal_out = +d.kcal_out;
    });

    const x = d3.scaleBand().range([0, width - margin.left - margin.right]).padding(0.1);
    const y = d3.scaleLinear().range([height - margin.top - margin.bottom, 0]);

    const svg = d3.select(`#${containerId}`)
    .append("svg")
    .attr("width", width + margin.left + margin.right)
    .attr("height", height + margin.top + margin.bottom)
    .append("g")
    .attr("transform", `translate(${margin.left},${margin.top})`);

    svg.append("text")
    .attr("x", (width - margin.left - margin.right) / 2)
    .attr("y", -margin.top / 2)
    .attr("text-anchor", "middle")
    .style("font-size", "16px")
    .style("text-decoration", "underline")
    .text("Calories In vs. Out");

    x.domain(data.map(d => d.date));
    y.domain([0, d3.max(data, d => Math.max(d.kcal_in, d.kcal_out))]);

    svg.append("g")
        .attr("class", "grid")
        .call(d3.axisLeft(y)
            .tickSize(-width + margin.left + margin.right)
            .tickFormat("")
        );

    svg.selectAll(".bar-in")
    .data(data)
    .enter()
    .append("rect")
    .attr("class", "bar-in")
    .attr("x", d => x(d.date))
    .attr("y", d => y(d.kcal_in))
    .attr("width", x.bandwidth() / 2)
    .attr("height", d => height -margin.top - margin.bottom - y(d.kcal_in))
    .attr("fill", "green");

    svg.selectAll(".bar-out")
        .data(data)
        .enter()
        .append("rect")
        .attr("class", "bar-out")
        .attr("x", d => x(d.date) + x.bandwidth() / 2)
        .attr("y", d => y(d.kcal_out))
        .attr("width", x.bandwidth() / 2)
        .attr("height", d => height - margin.top - margin.bottom - y(d.kcal_out))
        .attr("fill", "red");

    svg.append("g")
    .attr("transform", `translate(0,${height - margin.top - margin.bottom})`)
    .call(d3.axisBottom(x).tickFormat(d3.timeFormat("%b %d")))
    .selectAll("text")
    .attr("transform", "rotate(-45)")
    .style("text-anchor", "end");

    svg.append("g")
        .call(d3.axisLeft(y));

    svg.append("text")
        .attr("transform", `translate(${(width - margin.left - margin.right) / 2},${height - margin.bottom + 40})`)
        .style("text-anchor", "middle")
        .text("Date");

    svg.append("text")
        .attr("transform", "rotate(-90)")
        .attr("y", 0 - margin.left + 20)
        .attr("x", 0 - (height / 2))
        .attr("dy", "1em")
        .style("text-anchor", "middle")
        .text("Calories");

    //Add legend
    const legend = svg.append("g")
        .attr("transform", `translate(${width - margin.left - 100}, ${margin.top - 40})`);

    legend.append("rect")
        .attr("x", 0)
        .attr("y", 0)
        .attr("width", 18)
        .attr("height", 18)
        .attr("fill", "green");

    legend.append("text")
        .attr("x", 24)
        .attr("y", 9)
        .attr("dy", "0.35em")
        .style("text-anchor", "start")
        .text("Calories In");

    legend.append("rect")
        .attr("x", 0)
        .attr("y", 24)
        .attr("width", 18)
        .attr("height", 18)
        .attr("fill", "red");

    legend.append("text")
        .attr("x", 24)
        .attr("y", 33)
        .attr("dy", "0.35em")
        .style("text-anchor", "start")
        .text("Calories Out");
}

d3.json("/wtHistoryData").then(data => {
    createWtHistoryGraph(data, "wt-chart");
});

d3.json("/kcalSummaryData").then(kcal_data => {
    createKcalGraph(kcal_data, "kcal-chart");
});
