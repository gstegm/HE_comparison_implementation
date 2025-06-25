const greaterThan = require("./build/Release/greater_than")
const { performance, PerformanceObserver } = require('perf_hooks');
const pidusage = require('pidusage');
const fs = require('fs');
const { Parser } = require('json2csv');

const degreeThresholdTimestamp = 1262304000;  // Unix timestamp: Fri Jan 01 2010 00:00:00
const degreeIssuanceTimestamp = 1500000000;   // Unix timestamp: Fri Jul 14 2017 02:40:00

async function measureFunctionExecution(func, label, ...args) {
    performance.mark(`${label}-start`);
    const result = await func(...args);
    performance.mark(`${label}-end`);
    performance.measure(label, `${label}-start`, `${label}-end`);
    const { cpu, memory } = await pidusage(process.pid);
    const duration = performance.getEntriesByName(label)[0].duration;
    performance.clearMarks();
    performance.clearMeasures();
    return { cpu: Number(cpu.toFixed(2)), memory: Number((memory / 1024 / 1024).toFixed(2)), duration: Number(duration.toFixed(2)), result };
} 

function calculateStats(values) {
    // Filter out zero values and count the zeros
    const nonZeroValues = values.filter(value => value !== 0);
    const zeroCount = values.length - nonZeroValues.length;
    if (nonZeroValues.length === 0) {
        return { avg: 0, max: 0, min: 0, zeroCount };
    }

    const avg = nonZeroValues.reduce((a, b) => a + b, 0) / nonZeroValues.length;
    const max = Math.max(...nonZeroValues);
    const min = Math.min(...nonZeroValues);

    return { avg: Number(avg.toFixed(2)), max: Number(max.toFixed(2)), min: Number(min.toFixed(2)), zeroCount };
}

async function HEperformance(runs) {
    console.log("Running Homomorphic Encryption Performance Test.")
    const obs = new PerformanceObserver(() => {});
    obs.observe({ entryTypes: ['measure'] });

    let greaterThanStat = [];

    for (let i = 0; i < runs; i++) {
        console.log(`Run ${i + 1}/${runs}:`);

        const generateGreaterThanStat = await measureFunctionExecution(
            greaterThan,
            'greaterThan',
            degreeIssuanceTimestamp,
            degreeThresholdTimestamp
        );
        // remove result from statistics stack
        greaterThanStat.push({cpu: generateGreaterThanStat.cpu, memory: generateGreaterThanStat.memory, duration: generateGreaterThanStat.duration});
    };

    // measure
    const greaterThanCPU = greaterThanStat.map(stat => stat.cpu);
    const greaterThanMemory = greaterThanStat.map(stat => stat.memory);
    const greaterThanTime = greaterThanStat.map(stat => stat.duration);

    const greaterThanCPUStats = calculateStats(greaterThanCPU);
    const greaterThanMemoryStats = calculateStats(greaterThanMemory);
    const greaterThanTimeStats = calculateStats(greaterThanTime);


    console.log("\nGreaterThan Stats:");
    console.log(`CPU:\n\tAvg: ${greaterThanCPUStats.avg}%, Max: ${greaterThanCPUStats.max}%, Min: ${greaterThanCPUStats.min}%, ZEROs: ${greaterThanCPUStats.zeroCount}`);
    console.log(`Memory:\n\tAvg: ${greaterThanMemoryStats.avg}MB, Max: ${greaterThanMemoryStats.max}MB, Min: ${greaterThanMemoryStats.min}MB`);
    console.log(`Duration:\n\tAvg: ${greaterThanTimeStats.avg}ms, Max: ${greaterThanTimeStats.max}ms, Min: ${greaterThanTimeStats.min}ms`);

    const csvData = [];
    for (let i = 0; i < runs; i++) {
        csvData.push({
            run: i + 1,
            greaterThanCPU: greaterThanCPU[i],
            greaterThanMemory: greaterThanMemory[i],
            greaterThanTime: greaterThanTime[i],
        });
    };

    const fields = [
        'run',
        'greaterThanCPU', 'greaterThanMemory', 'greaterThanTime',
    ];
    const json2csvParser = new Parser({ fields });
    const csv = json2csvParser.parse(csvData);

    fs.writeFileSync('./HE_performance_data_OpenFHE.csv', csv);
    console.log('Performance data saved to HE_performance_data_OpenFHE.csv');
}

HEperformance(10);