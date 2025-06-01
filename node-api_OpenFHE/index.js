const greaterThan = require("./build/Release/greater_than")

result = greaterThan(1742627779, 1742628527)
for (i=0; i<100; i++) {
    result = greaterThan(1742627779, 1742628527)
}
console.log(result)
console.log(typeof(result))