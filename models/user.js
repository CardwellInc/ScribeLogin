const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const passportLocalMongoose = require('passport-local-mongoose');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    username: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    cmwcode: {
        type: String,
        required: true,
    }
});

userSchema.pre('save', function(next) {
    if(this.isModified('password')){
        bcrypt.hash(this.password, 10, (err, hash) => {
            if(err) return next(err);

            this.password = hash;
            next();
        });
    }
});


userSchema.methods.comparePassword = async function (password) {
    if(!password) throw new Error('Password cannot Compare.');

    try {
        const result = await bcrypt.compare(password, this.password);
        return result;
    } catch (error) {
        console.log('Error While Comparing Passwords', error.message);
    };
};

userSchema.statics.isThisUsernameInUse = async function(username) {
    if (!username) throw new Error('Invalid Username');
    try {
        const user = await this.findOne({ username });
        if (user) return false;

        return true;
    } catch (error) {
        console.log('error with isThisUsernameInUse', error.message)
        return false;
    };
};


userSchema.plugin(passportLocalMongoose);




module.exports = mongoose.model('User', userSchema);