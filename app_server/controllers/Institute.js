var mongoose = require('mongoose');
var express = require('express');
var User = require('../models/entity');
var certificate = require('../models/certificate');
var degree = require('../models/degree');
const bcrypt = require('bcryptjs');
var XLSX = require('xlsx')
var recepient = require('../models/recepient');
var student = require('../models/student_info');
var nodemailer = require('nodemailer');
var crypto = require('crypto')
var blockchain = require('../controllers/BlockChain')
var merkle = require('../controllers/merkletree')
var fastRoot = require('../controllers/fastRoot')
var merkleProof = require('../controllers/proof')
const uuidv4 = require('uuid/v4');
//const
  //  Web3 = require('web3')
const https = require('https')



module.exports.UpdatePublicKey = function (req, res) {
    const id = req.params.id;
    const pkey = req.params.pkey;


    const email = req.params.email;
    // console.log("id", id);
    // console.log("pkey", pkey);
    // console.log("email", email);

    student.updateOne({
        'data.id': id
    }, {
        '$set': {
            'data.$.pkey': pkey,
        }
    }, (err, result) => {
        if (err) {
            console.log(err);
            throw err;
        } else {
            console.log("Result---->", result);
            console.log("Public Key Updated");
        }
    })

    console.log("id", id);
    console.log("pkey", pkey);
/*
    // Assuming Public Key is now updated
    var institutePubKey = "0x6e6f07247161e22e1a259196f483ccec21dfbff9"
    console.log("Publishing transaction on Blockchain from Central Authority to Institute")
    fromPubKey = process.env.WALLET_ADDRESS
    fromPvtKey = process.env.WALLET_PRIVATE_KEY
    toPubKey = institutePubKey
    data = ""
    const txid = blockchain.publishOnBlockchain(data, fromPvtKey, fromPubKey, toPubKey, 5)
    console.log(txid)

    res.send(200)*/
    temp = {};
    temp['response'] = "Ok";
    res.send(temp)
}


module.exports.GetDegrees = function (req, res) {
    const pkey = req.params.pkey;
    console.log("get certificate called");
    console.log("pubkey", pkey);
    degree.find({
        'degree.Public Key': pkey
    }, function (err, res2) {
        if (err) {
            console.log(err)
        } else {
            console.log(res2)
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(res2));
        }
    })
}


module.exports.ViewDegree = function (req, res) {
    const degreeid = req.params.degreeid
    console.log("View Degree called!")
    console.log("Degree ID", degreeid)

    degree.findById(degreeid, function (err, res2) {
        if (err) {
            console.log(err)
        } else {

            res2 = res2.degree[0]
            
            console.log(res2)
            
            recepient.find({
                InstituteID: req.session.uid
            }, (err, recep) => {


                var InstituteName = req.session.name;
               res.render('Institute/Degree', {
                    recep,
                    InstituteName,
                    res2,degreeid
                });
                /*degree=res2
                res.render('Institute/CertificateDraft', {
                    degree,
                    InstituteName
                })*/
        

            })


        }
    })
}


module.exports.CreateDegree = function (req, res) {
    const title = req.body.title;
    var newcertificate = new certificate({
        Title: title,
        Fields: req.body.feature
    });

    newcertificate["DateofCreation"] = Date.now();
    console.log(newcertificate);
    newcertificate.save();
    res.redirect('/Institute/Certificate/Draft');
}
module.exports.DraftCertificate = function (req, res) {
    certificate.find({}, function (err, degree) {
        var InstituteName = req.session.name;
        res.render('Institute/CertificateDraft', {
            degree,
            InstituteName
        })
    })
}
module.exports.loadCertificate = function (req, res) {
    certificate.findById(req.params.id, function (err, degree) {
        recepient.find({
            InstituteID: req.session.uid
        }, (err, recep) => {

            var InstituteName = req.session.name;

            res.render('Institute/Certificate', {
                degree,
                recep,
                InstituteName
            });
        })
    });


}

module.exports.setPassword = function (req, res) {

    bcrypt.hash(req.body.password2, 10, function (err, hash) {
        if (err) {
            console.log(err);
            throw err;
        }
        User.findOneAndUpdate({
            _id: req.session.uid
        }, {
            $set: {
                Password: hash
            }
        }, (error, result) => {
            if (error)
                console.log(error);

        });

        res.redirect('/Institute/landing2');
    });

}

module.exports.uploadRecepient = function (req, res) {

    console.log("in server side of upload ercep");

    var workbook = XLSX.readFile('./public/Uploads/' + req.file.filename);
    var sheet_name_list = workbook.SheetNames;
    var xlData = XLSX.utils.sheet_to_json(workbook.Sheets[sheet_name_list[0]]);
    console.log(xlData);


    xlData.forEach((row) => {
        var temp = uuidv4();;
        row['id'] = temp
        row['pkey'] = ""
    })
    let studentInfo = new student({
        data: xlData,
        InstituteID: req.session.uid,
        Name: req.file.filename.slice(0, -5)
    });

    studentInfo.save(function (err, result) {
        if (err) {
            console.log(err);
            throw err;
        } else {
            console.log(result);

        }
    });

    console.log(xlData.length)
    /*
    var wb = XLSX.readFile("./public/Uploads/"+req.file.filename);
    console.log(wb);*/

    let newRecepient = new recepient({
        Status: "Pending",
        Records: xlData.length,
        FilePath: req.file.filename,
        IssueDate: Date.now(),
        InstituteID: req.session.uid,
        Name: req.file.filename.slice(0, -5)

    });

    newRecepient.save(function (err, result) {
        if (err) {
            console.log(err);
            throw err;
        } else {
            console.log(result);

            res.send({
                result
            });
        }
    });

}


function
sha256(data) {

    return
    crypto.createHash('sha256').update(data).digest()

}


module.exports.DeleteDegreeTemplate = function (req, res) {

    recordToDelete = req.body.rec;



    if (recordToDelete instanceof String || typeof recordToDelete === 'string') {
        certificate.findOneAndDelete({
            _id: recordToDelete
        }, (err, result) => {
            if (err) {
                console.log(err);
                throw err;
            } else {
                console.log("Record Deleted");
                console.log(result);
                res.redirect('Institute/Certificate/Draft')

            }

        })
    } else {



        certificate.deleteMany({
            _id: {
                $in: recordToDelete
            }
        }, (err, result) => {

            if (err) {
                console.log(err);
                throw err;
            } else {
                console.log("Record Deleted");
                console.log(result);
                res.redirect('Institute/Certificate/Draft')

            }


        })

    }

}



module.exports.loadRecepient = function (req, res) {
    recepient.find({
        InstituteID: req.session.uid
    }, (err, recep) => {

        var InstituteName = req.session.name;

        res.render('Institute/Recipients', {
            recep,
            InstituteName
        });
    })


}


module.exports.IssueCertificates =
    function (req,
        res) {

        console.log(req.body.templateid);

        var
            path = req.body.recepient +
            ".xlsx";

        console.log(path);



        var
            workbook = XLSX.readFile('./public/Uploads/' +
                req.body.recepient +
                ".xlsx");

        var
            sheet_name_list = workbook.SheetNames;

        var
            xlData = XLSX.utils.sheet_to_json(workbook.Sheets[sheet_name_list[0]]);



        certificate.findById({

            _id: req.body.templateid

        }, function (err,
            result) {

            if (err) {

                console.log(err);

                throw err

            }



            var
                JSONDATA = [];

            for (let
                    index =
                    0; index <
                xlData.length; index++) {



                var
                    temp = {};

                const
                    element = xlData[index];



                result.Fields.forEach((attribute) => {

                    var
                        columnName = attribute;

                    temp[columnName] =
                        element[attribute];

                });

                temp['Public Key'] =   "0x6e6F07247161E22E1a259196F483cCEC21dfBfF9"

                JSONDATA.push(temp);

            };


            console.log(JSONDATA);



            // Computing hashes of JSONDATA to construct merkle tree

            var
                certHashes = []

            for (let
                    i =
                    0; i <
                JSONDATA.length; ++i) {

                dataHash =
                    sha256(JSON.stringify(JSONDATA[i]))

                certHashes.push(dataHash)

            }



            console.log("\nHashes of Certificates\n")

            console.log(certHashes.map(x =>
                x.toString('hex')))



            var
                tree = merkle(certHashes,
                    sha256)



            console.log("Printing Tree in Hex:\n")

            console.log(tree.map(x =>
                x.toString('hex')))



            var
                root = fastRoot(certHashes,
                    sha256)

            console.log("Root:\t" +
                root.toString('hex'))



            // Computing Proofs for each Certificate

            var
                proofs = []

            for (let
                    i =
                    0; i <
                certHashes.length; ++i) {

                var
                    proof = merkleProof(tree,
                        certHashes[i])

                if (proof ===
                    null) {

                    console.error('No proof exists!')

                }

                proofs.push(proof)

                // JSONDATA[i]['Proof'] = proof.map(x => x && x.toString('hex'))

                JSONDATA[i]['Proof'] =
                    JSON.stringify(proof)

                console.log(JSONDATA[i])

                console.log("Proof for Certificate " +
                    i +
                    "\n")

                console.log(proof.map(x =>
                    x && x.toString('hex')))

            }


            // Verifying Proof for each Certificate

            for (let
                    i =
                    0; i <
                certHashes.length; ++i) {

                console.log(merkleProof.verify(proofs[i],
                    certHashes[i],
                    root,
                    sha256))

            }



            console.log("Publishing root on Blockchain")

            fromPubKey =
                process.env.WALLET_ADDRESS

            fromPvtKey =
                process.env.WALLET_PRIVATE_KEY

            toPubKey =
                process.env.DESTINATION_WALLET_ADDRESS

            const
                txid = blockchain.publishOnBlockchain(root.toString('hex'),
                    fromPvtKey,
                    fromPubKey, toPubKey,
                    5)

            // console.log(txid)



            txid.then(function (res) {

                for (let
                        i =
                        0; i <
                    JSONDATA.length; ++i) {

                    JSONDATA[i]['instituteTxHash'] =
                        res

                    console.log("Certificates with transactions " +
                        i +
                        "\n")

                    console.log(JSONDATA[i])

                }



                for (let
                        i =
                        0; i <
                    JSONDATA.length; ++i) {

                    var
                        newdegree = new
                    degree({

                        degree: JSONDATA[i]

                    });

                    newdegree.save(function (err,
                        result) {

                        if (err) {

                            console.log(err);

                            throw err;

                        } else {

                            console.log(result);

                        }

                    });

                }

            }, function (err) {

                console.log(err)

            })


        })

        res.redirect('back')

    }



    module.exports.VerifyDegree =
    function (req,
        res) {

        // root will actually be obtained from the transaction (op return field) from institute's public key to itself

        /* 

        Steps:

        1. get certificate from db using degree id

        2. get institute public key from degree

        3. ensure that it is verified by HEC

        4. verify its proof 

        */

        degreeid =
            req.params.degreeid

        // hash = "86f83489f61f468c30d6cf7578fcab6dad0d73ff0fc005c5424c619996f40a6b"

        // root = "e9e656451007174ea2b2c472bfb9ae9c833cd16bf5d3c2a677aed05d160dbcd0"

        degree.findById(degreeid,
            function (err,
                res2) {

                if (err) {

                    console.log(err)

                } else {

                    console.log("Verifying!")

                    proof =
                        res2.degree[0].Proof



                    // Calculate Degree Hash

                    deg =
                        res2.degree[0]

                    txhash =
                        deg.instituteTxHash

                    delete
                    deg["Proof"]

                    delete
                    deg["instituteTxHash"]

                    console.log(deg)

                    console.log("Degree Hash")

                    hash =
                        sha256(JSON.stringify(deg))

                    console.log(hash)


                    // Retrieve Merkle Root

                    // 
                    https: //api-rinkeby.etherscan.io/api?module=proxy&action=eth_getTransactionByHash&txhash=0x55969c2660e26a21ebf531f6ea94fe6a4e672bc33154587422d98473045041c5&apikey=899QCPY36YQZFIC6Q8FXZGZM5R7RU1U1C9



                        var options = {
                                hostname: 'api-rinkeby.etherscan.io',
                                port: 443,
                                path: '/api?module=proxy&action=eth_getTransactionByHash&txhash=' +txhash + '&apikey=899QCPY36YQZFIC6Q8FXZGZM5R7RU1U1C9s',
                                 method: 'GET'
                            }


                    const webreq = https.request(options, (webres) => {

                            console.log(`statusCode:${webres.statusCode}`)


                            webres.on('data', (d) => {

                                // process.stdout.write(d)

                                console.log(d)

                                apires =
                                    JSON.parse(d)

                                if (!apires || !apires.result) {

                                    res.send("false")

                                    return;

                                }

                                extraData =
                                    apires.result.input.substring(2,
                                        apires.result.input.length)

                                // apires = JSON.stringify(apires.result.input)

                                tbl = {}

                                tbl["30"] =
                                    "0"

                                tbl["31"] =
                                    "1"

                                tbl["32"] =
                                    "2"

                                tbl["33"] =
                                    "3"

                                tbl["34"] =
                                    "4"

                                tbl["35"] =
                                    "5"

                                tbl["36"] =
                                    "6"

                                tbl["37"] =
                                    "7"

                                tbl["38"] =
                                    "8"

                                tbl["39"] =
                                    "9"

                                tbl["61"] =
                                    "a"

                                tbl["62"] =
                                    "b"

                                tbl["63"] =
                                    "c"

                                tbl["64"] =
                                    "d"

                                tbl["65"] =
                                    "e"

                                tbl["66"] =
                                    "f"

                                hexStr =
                                    ""

                                extraData.match(/..?/g).map(value =>
                                    hexStr += tbl[value])

                                console.log(hexStr)

                                root =
                                    hexStr

                                proof =
                                    JSON.parse(proof)

                                // console.log(proof)

                                var
                                    bufArr = []

                                for (var
                                        key in proof) {

                                    console.log("iteration")

                                    console.log(key)

                                    if (proof[key])

                                        bufArr.push(Buffer.from(proof[key]))

                                    else

                                        bufArr.push(null)

                                    // if(data != null)

                                    // proof.data = Buffer.from(data)

                                }

                                // root = "e9e656451007174ea2b2c472bfb9ae9c833cd16bf5d3c2a677aed05d160dbcd0"

                                console.log(bufArr.map(x =>
                                    x && x.toString('hex')))

                                resBool =
                                    merkleProof.verify(bufArr,
                                        new Buffer(hash,
                                            'hex'), new Buffer(root,
                                            'hex'), sha256)

                                console.log(resBool)

                                res.send(resBool)

                            })

                        })


                    webreq.on('error', (error) => {

                        console.error(error)

                    })


                    webreq.end()

                }

            })

    }






module.exports.sendEmail = function (req, res) {
    console.log("Send Email!");
    var emails = [];
    var studentId = [];
    var name = [];
    student.find({
        InstituteID: req.session.uid
    }, {
        _id: 0,
        data: 1
    }, function (err, arr) {
        data_arr = arr.map(function (u) {
            return u.data;
        });
        for (i = 0; i < data_arr.length; i++) {
            for (j = 0; j < data_arr[i].length; j++) {
                emails.push(data_arr[i][j].Email);
                studentId.push(data_arr[i][j].id);
                name.push(data_arr[i][j].Recepient);

            }
        }
        if (emails.length == 0) {
            console.log("No recipients found for sending Invites!");
            return;
        }
        email_str = emails.toString();
        console.log(email_str);

        var transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'edcertsweb@gmail.com',
                pass: 'blockchain'
            }
        });

         emails.forEach((e, index) => {

            var mailOptions = {
                from: 'edcertsweb@gmail.com',
                to: e,
                subject: 'Invitation for receiving certificate | Edcerts',
                text: 'Dear ' + name[index] + '\n\nYou have been sent an invitation to add the ' + req.session.name + ' in Edcerts application. This will allow you to receive certificate from the institute. Your institute id is ' + req.session.uid + '\nPlease click on the below link to continue:\n\n https://edcert.herokuapp.com/UpdatePublicKey/' + studentId[index] + ' \n\nRegards,\nTeam Edcerts'
            };

            transporter.sendMail(mailOptions, function (error, info) {
                if (error) {
                    console.log(error);
                } else {
                    console.log('Email sent: ' + info.response);
                }
            });
        })
    });

    res.redirect('/Institute/Recipients')
}


module.exports.LoadCertificateIssued = function (req, res) {
    var InstituteName = req.session.name;

    res.render('Institute/CertificateIssued', {
        InstituteName
    });



}

module.exports.DeleteRecepientList = function (req, res) {

    console.log("In Deete recep")
    recordToDelete = req.body.rec;



    if (recordToDelete instanceof String || typeof recordToDelete === 'string') {
        recepient.findOneAndDelete({
            _id: recordToDelete
        }, (err, result) => {
            if (err) {
                console.log(err);
                throw err;
            } else {
                console.log("Record Deleted");
                console.log(result);
                res.redirect('Institute/Recipients')

            }

        })
    } else {



        recepient.deleteMany({
            _id: {
                $in: recordToDelete
            }
        }, (err, result) => {

            if (err) {
                console.log(err);
                throw err;
            } else {
                console.log("Record Deleted");
                console.log(result);
                res.redirect('Institute/Recipients')

            }


        })

    }
}


module.exports.UpdateInstitutePublicKey =function (req,res) {
/*
    console.log(req.params.pkey);
var pkey=req.params.pkey
  User.findOneAndUpdate({
         _id:req.session.uid
  },{$set:{PublicKey:pkey} }, (err, result) => {


    
        var InstituteName = req.session.name;

        res.render('Institute/Recipients', {
            recep,
            InstituteName
        });

        console.log(result);
    })

    res.send(200);
  */

 const id = req.params.id;

const pkey = req.params.pkey;



console.log("id", id);

console.log("pkey", pkey);


// Assuming Public Key is now updated

var institutePubKey = "0x6e6f07247161e22e1a259196f483ccec21dfbff9"

console.log("Publishing transaction on Blockchain from Central Authority to Institute")

fromPubKey = process.env.WALLET_ADDRESS

fromPvtKey = process.env.WALLET_PRIVATE_KEY

toPubKey = institutePubKey

data = ""

const txid = blockchain.publishOnBlockchain(data,
     fromPvtKey,
     fromPubKey, toPubKey,
     5)

console.log(txid)



res.send(200)

}