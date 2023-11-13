## Description:

## Admin Checklist:
- [ ] You have updated documentation in symcrypt.h to reflect any changes in behavior
- [ ] You have updated CHANGELOG.md to reflect any changes in behavior
- [ ] You have updated symcryptunittest to exercise any new functionality
- [ ] If you have introduced any symbols in symcrypt.h you have updated production and test dynamic export symbols (exports.ver / exports.def / symcrypt.src) and tested the updated dynamic modules with symcryptunittest
- [ ] If you have introduced functionality that varies based on CPU features, you have manually tested with and without relevant features
- [ ] If you have made significant changes to a particular algorithm, you have checked that performance numbers reported by symcryptunittest are in line with expectations
- [ ] If you have added new algorithms/modes, you have updated the status indicator text for the associated modules if necessary
