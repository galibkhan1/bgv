function flattenObject(obj, parentKey = '', res = {}) {
    for (const key in obj) {
        if (!obj.hasOwnProperty(key)) continue;
        const propName = parentKey ? `${parentKey}.${key}` : key;
        if (typeof obj[key] === 'object' && obj[key] !== null) {
            flattenObject(obj[key], propName, res);
        } else {
            res[propName] = obj[key];
        }
    }
    return res;
}


function jsonToTable(data) {
    if (!data) return '<p>No data available</p>';

    if (Array.isArray(data)) {
        if (data.length === 0) return '<p>No records found</p>';

        const headers = Object.keys(data[0]);
        let table = '<table><thead><tr>';
        headers.forEach(header => {
            table += `<th>${header}</th>`;
        });
        table += '</tr></thead><tbody>';

        data.forEach(item => {
            table += '<tr>';
            headers.forEach(header => {
                let val = item[header];
                if (typeof val === 'object' && val !== null) {
                    val = `<pre>${JSON.stringify(val, null, 2)}</pre>`;
                }
                table += `<td>${val !== null ? val : ''}</td>`;
            });
            table += '</tr>';
        });

        table += '</tbody></table>';
        return table;
    }

    if (typeof data === 'object') {
        let table = '<table>';
        for (const key in data) {
            if (Object.hasOwnProperty.call(data, key)) {
                let val = data[key];
                if (typeof val === 'object' && val !== null) {
                    val = `<pre>${JSON.stringify(val, null, 2)}</pre>`;
                }
                table += `<tr><th>${key}</th><td>${val !== null ? val : ''}</td></tr>`;
            }
        }
        table += '</table>';
        return table;
    }

    return `<p>${data}</p>`;
}

const buttons = document.querySelectorAll('nav button');
const pages = document.querySelectorAll('.page');

buttons.forEach(button => {
    button.addEventListener('click', () => {
        buttons.forEach(btn => btn.classList.remove('active'));
        pages.forEach(page => page.classList.remove('active'));

        button.classList.add('active');

        switch(button.id) {
            case 'btn-pan':
                document.getElementById('page-pan').classList.add('active');
                break;
            case 'btn-bank':
                document.getElementById('page-bank').classList.add('active');
                break;
            case 'btn-digilocker':
                document.getElementById('page-digilocker').classList.add('active');
                break;
            case 'btn-e-sign':
                document.getElementById('page-e-sign').classList.add('active');
                break;
        }
    });
});


function verifyPan() {
    const pan = $('#panInput').val().toUpperCase().trim();
    const resultDiv = $('#result');
    resultDiv.html('');

    if (!pan) {
        resultDiv.html('<span style="color:red;">Please enter a PAN number.</span>');
        return;
    }

    const regex = /^[A-Z]{5}[0-9]{4}[A-Z]$/;
    if (!regex.test(pan)) {
        resultDiv.html('<span style="color:red;">Invalid PAN Number format.</span>');
        return;
    }

    resultDiv.html('Checking PAN...');

    $.ajax({
        url: '/verify-pan',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ pan }),
        success: function(response) {
            resultDiv.html(jsonToTable(response));
        },
        error: function(xhr) {
            const err = xhr.responseJSON?.error || 'Something went wrong!';
            resultDiv.html('<span style="color:red;">Error: ' + err + '</span>');
        }
    });
}


function verifyBank() {
    const accountNumber = $('#accountNumber').val().trim();
    const ifsc = $('#ifscCode').val().toUpperCase().trim();
    const resultDiv = $('#bankResult');
    resultDiv.html('');

    if (!accountNumber || !ifsc) {
        resultDiv.html('<span style="color:red;">Please fill in both account number and IFSC code.</span>');
        return;
    }

    const ifscRegex = /^[A-Z]{4}0[A-Z0-9]{6}$/;
    if (!ifscRegex.test(ifsc)) {
        resultDiv.html('<span style="color:red;">Invalid IFSC code format.</span>');
        return;
    }

    resultDiv.html('Verifying bank details...');

    $.ajax({
        url: '/verify-bank',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ accountNumber, ifsc }),
        success: function(response) {
            resultDiv.html(jsonToTable(response));
        },
        error: function(xhr) {
            const err = xhr.responseJSON?.error || 'Something went wrong!';
            resultDiv.html('<span style="color:red;">Error: ' + err + '</span>');
        }
    });
}


function startDigilockerConsent() {
    const aadhaar = $('#aadhaarNumber').val().trim();
    const resultDiv = $('#digilockerDocsResult');
    const requestInfoDiv = $('#digilockerRequestInfo');
    const requestIdSpan = $('#digilockerRequestId');
    const loginUrlLink = $('#digilockerLoginUrl');

    resultDiv.html('');
    requestInfoDiv.hide();
    requestIdSpan.text('');
    loginUrlLink.attr('href', '').text('');

    if (!aadhaar) {
        resultDiv.html('<span style="color:red;">Please enter Aadhaar number.</span>');
        return;
    }

    if (!/^\d{12}$/.test(aadhaar)) {
        resultDiv.html('<span style="color:red;">Invalid Aadhaar number format.</span>');
        return;
    }

    window.location.href = '/digilocker/create-request';
}

function checkDigilockerRequestStatus() {
    const requestId = $('#digilockerRequestId').text().trim();
    const resultDiv = $('#digilockerDocsResult');

    if (!requestId) {
        resultDiv.html('<span style="color:red;">No Request ID found.</span>');
        return;
    }

    resultDiv.html('Checking DigiLocker request status...');

    $.ajax({
        url: '/digilocker/request-status',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ id: requestId }),
        success: function(response) {
            if (response.status) {
                const statusLower = response.status.toLowerCase();
                let html = `<p><strong>Status:</strong> ${response.status}</p>`;
                resultDiv.html(html);

                
                if (response.aadhaar) {
                    let aadhaarHtml = "<h3>Aadhaar XML</h3>";
                    const flatAadhaar = flattenObject(response.aadhaar);
                    aadhaarHtml += jsonToTable(flatAadhaar);
                    resultDiv.append(aadhaarHtml);
                }

                if (['completed', 'success', 'done', 'authenticated'].includes(statusLower)) {
                    if (Array.isArray(response.documents) && response.documents.length > 0) {
                        let docHtml = "<h3>DigiLocker Documents:</h3>";
                        docHtml += jsonToTable(response.documents);
                        resultDiv.append(docHtml);
                    } else {
                        resultDiv.append('<p>No DigiLocker documents found.</p>');
                    }

                } else if (statusLower === 'unauthenticated') {
                    resultDiv.append('<p>Please <a href="' + response.url + 
                        '" target="_blank" rel="noopener noreferrer">log in to DigiLocker</a> to complete the consent process. Then click "Check Request Status".</p>');

                } else {
                    if (response.documents) {
                        if (Array.isArray(response.documents)) {
                            resultDiv.append(jsonToTable(response.documents));
                        } else {
                            resultDiv.append(jsonToTable([response.documents]));
                        }
                    }
                }

            } else if (response.error) {
                resultDiv.html('<span style="color:red;">Error: ' + response.error + '</span>');
            } else {
                resultDiv.html('<span style="color:red;">Unexpected response from server.</span>');
            }
        },
        error: function(xhr) {
            const err = xhr.responseJSON?.error || 'Something went wrong!';
            resultDiv.html('<span style="color:red;">Error: ' + err + '</span>');
        }
    });
}


function startESign() {
    const aadhaar = $('#esignAadhaar').val().trim();
    const mobile = $('#esignMobile').val().trim();
    const fileInput = $('#esignFileInput')[0];
    const resultDiv = $('#esignResult');

    resultDiv.html('');

    if (!aadhaar || !/^\d{12}$/.test(aadhaar)) {
        resultDiv.html('<span style="color:red;">Please enter a valid 12-digit Aadhaar number.</span>');
        return;
    }

    if (!mobile || !/^\d{10}$/.test(mobile)) {
        resultDiv.html('<span style="color:red;">Please enter a valid 10-digit mobile number.</span>');
        return;
    }

    if (!fileInput.files.length) {
        resultDiv.html('<span style="color:red;">Please select a PDF file to sign.</span>');
        return;
    }

    const file = fileInput.files[0];
    if (file.type !== "application/pdf") {
        resultDiv.html('<span style="color:red;">Only PDF files are allowed.</span>');
        return;
    }

    const reader = new FileReader();

    reader.onload = function(e) {
        const base64File = e.target.result.split(',')[1];

        resultDiv.html('Starting e-sign process...');

        $.ajax({
            url: '/esign/start',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                aadhaar,
                mobile,
                fileName: file.name,
                fileContent: base64File
            }),
            success: function(response) {
                if (response.requestId && response.url) {
                    $('#esignRequestId').text(response.requestId);
                    $('#esignLoginUrl').attr('href', response.url).text('Open e-Sign Login');
                    $('#esignRequestInfo').show();
                    resultDiv.html('<span style="color:green;">E-sign process started. Click "Open e-Sign Login" to proceed.</span>');
                } else if (response.error) {
                    resultDiv.html('<span style="color:red;">Error: ' + response.error + '</span>');
                } else {
                    resultDiv.html('<span style="color:red;">Unexpected response from server.</span>');
                }
            },
            error: function(xhr) {
                const err = xhr.responseJSON?.error || 'Something went wrong!';
                resultDiv.html('<span style="color:red;">Error: ' + err + '</span>');
            }
        });
    };

    reader.onerror = function() {
        resultDiv.html('<span style="color:red;">Failed to read file.</span>');
    };

    reader.readAsDataURL(file);
}

function checkESignStatus() {
    const requestId = $('#esignRequestId').text().trim();
    const resultDiv = $('#esignResult');

    if (!requestId) {
        resultDiv.html('<span style="color:red;">No e-sign Request ID found.</span>');
        return;
    }

    resultDiv.html('Checking e-sign request status...');

    $.ajax({
        url: '/esign/status',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ requestId }),
        success: function(response) {
            if (response.status) {
                let html = `<p><strong>Status:</strong> ${response.status}</p>`;
                resultDiv.html(html);

                const statusLower = response.status.toLowerCase();

                if (['completed', 'success', 'done', 'signed'].includes(statusLower)) {
                    if (response.signedDocument) {
                        html += `<h3>Signed Document:</h3>`;
                        html += `<a href="${response.signedDocument.url}" target="_blank" rel="noopener noreferrer">${response.signedDocument.fileName || 'Download Document'}</a>`;
                        resultDiv.html(html);
                    } else {
                        resultDiv.append('<p>No signed document found.</p>');
                    }
                } else if (statusLower === 'pending') {
                    resultDiv.append('<p>E-sign is pending. Please complete the e-sign process by clicking on "Open e-Sign Login".</p>');
                } else {
                    resultDiv.append('<p>Status: ' + response.status + '</p>');
                }
            } else if (response.error) {
                resultDiv.html('<span style="color:red;">Error: ' + response.error + '</span>');
            } else {
                resultDiv.html('<span style="color:red;">Unexpected response from server.</span>');
            }
        },
        error: function(xhr) {
            const err = xhr.responseJSON?.error || 'Something went wrong!';
            resultDiv.html('<span style="color:red;">Error: ' + err + '</span>');
        }
    });
}


$(document).ready(() => {
    $('#verifyPanBtn').click(verifyPan);
    $('#verifyBankBtn').click(verifyBank);
    $('#startDigilockerBtn').click(startDigilockerConsent);
    $('#checkStatusBtn').click(checkDigilockerRequestStatus);
    $('#startESignBtn').click(startESign);
    $('#checkESignStatusBtn').click(checkESignStatus);


    const urlParams = new URLSearchParams(window.location.search);
    const success = urlParams.get('success');
    const digilockerId = urlParams.get('id');
    
    if (success === 'True' && digilockerId) {
        $('nav button').removeClass('active');
        $('.page').removeClass('active');

        $('#btn-digilocker').addClass('active');
        $('#page-digilocker').addClass('active');

        $('#digilockerRequestId').text(digilockerId);
        $('#digilockerRequestInfo').show();

        checkDigilockerRequestStatus();
        window.history.replaceState({}, document.title, "/");
    }
});