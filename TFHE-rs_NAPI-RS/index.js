const addon = require("./tfhe_comparison.node");
const pidusage = require('pidusage');
//const clientkey = vec[0];
//const serverkey = vec[1];
//const publickey = vec[2];

function test () {
    const vec = addon.getKeys();
    const enc_a = addon.encrypt(1743242617, vec[0]);
    const enc_b = addon.encryptPublicKey(-2200565386, vec[2]);
    const enc_comp = addon.greaterThan(enc_a, enc_b, vec[1]);
    const dec_comp = addon.decrypt(enc_comp, vec[0]);
    console.log(dec_comp);
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

let stat = [];



async function HEperformance(runs) {
    for (let i = 0; i < runs; i++) {
        console.log(`Run ${i + 1}/${runs}:`);

        const testStat = await measureFunctionExecution(
            test,
            'test'
        );
        stat.push(testStat);

    }

    const usageCPU = stat.map(stat => stat.cpu);
    const usageMemory = stat.map(stat => stat.memory);
    const usageTime = stat.map(stat => stat.duration);

    const statCPU = calculateStats(usageCPU);
    const statMemory = calculateStats(usageMemory);
    const statTime = calculateStats(usageTime);


    console.log("\nVerifier Setup Stats:");
    console.log(`CPU:\n\tAvg: ${statCPU.avg}%, Max: ${statCPU.max}%, Min: ${statCPU.min}%, ZEROs: ${statCPU.zeroCount}`);
    console.log(`Memory:\n\tAvg: ${statMemory.avg}MB, Max: ${statMemory.max}MB, Min: ${statMemory.min}MB`);
    console.log(`Duration:\n\tAvg: ${statTime.avg}ms, Max: ${statTime.max}ms, Min: ${statTime.min}ms`);


}
//for(i=0;i<100;i++) {
//    addon.allInOne();
//}

HEperformance(100);