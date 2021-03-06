//Made by Christopher Michael Wilson Cardwell
document.getElementById("petnum").addEventListener('change', Namefunc);
document.getElementById('NumPets').addEventListener('change', NumPetFunc);
document.getElementById('passedpetdd').addEventListener('change', Petpassed);
document.getElementById('BKdate').addEventListener('change', RSdate);
document.getElementById('ugdgbalowedquestion').addEventListener('change', UGDGbalowed);
document.getElementById('BODDRMQR').addEventListener('change', MedRemoveBal);

document.getElementById("QRKingbtn").addEventListener("click", QRking);
document.getElementById("SubmitUGDGbtn").addEventListener("click", UGDGform);
document.getElementById("PDBsubmitbtn").addEventListener("click", PDBnotes);
document.getElementById("AddDispo").addEventListener("click", DispoEnding);
document.getElementById("RSUbtnclick").addEventListener("click", RSUFunc);
document.getElementById("WRPFSubmit").addEventListener("click", WaiveRPF);
document.getElementById("WFFSubmit").addEventListener("click", WaivePymt);
document.getElementById("submitbgenbtn").addEventListener("click", BGENExNotes);
document.getElementById("RMsubmitbtn").addEventListener("click", RemovingMedsSubmit);

document.getElementById("Reset-button").addEventListener("click", resetall);

function resetall() {
  if (confirm("Are you sure you want to Reset?")) {
      location.reload();
  }
}

function MedRemoveBal() {
  let MRBO = document.getElementById('BODDRMQR')

    if (MRBO.value == "No"){
        var hidden = 'none';
        document.getElementById('AMTOWEDRM').style.display = hidden;
  } else if (MRBO.value == "Yes"){
    var style = this.value == "Yes" ? 'block' : 'none';
    document.getElementById('AMTOWEDRM').style.display = style;
  }
}


function RSUFunc() {
  var x = document.getElementById("reviewinv").value;

  var today = new Date(x);{
    var dd = today.getDate();
    var mm = (today.getMonth()+1);
    var yyyy = today.getFullYear();
    
  }

  today = mm+'/'+dd+'/'+yyyy;
  console.log(today)

  let RSUresult = "The services that added to your balance can be broken down on the invoices, available in your pets medical history. Any invoice from "+ today +" to present would show you usage for the plan year. There are two pricing columns to review. ???Regular Fee??? reflects the actual cost of the services.???Your fee??? is what you paid out of that portion. The difference between those two totals would apply to the services balance.";

  document.getElementById("RSUtest").innerHTML = RSUresult;

}



function Namefunc() {
  let Titan = document.getElementById('petnum')

  if (Titan.value == "1"){
      var hidden = 'none';
      document.getElementById('One-Pet').style.display = style;
      document.getElementById('Two-Pet').style.display = hidden;
      document.getElementById('Three-Pet').style.display = hidden;
      document.getElementById('Four-Pet').style.display = hidden;
      document.getElementById('Five-Pet').style.display = hidden;
      document.getElementById('Six-Pet').style.display = hidden; 
  }
  else if (Titan.value == "2"){
      var style = this.value == "2" ? 'block' : 'none';
      var hidden = 'none';
      document.getElementById('One-Pet').style.display = style;
      document.getElementById('Two-Pet').style.display = style;
      document.getElementById('Three-Pet').style.display = hidden;
      document.getElementById('Four-Pet').style.display = hidden;
      document.getElementById('Five-Pet').style.display = hidden;
      document.getElementById('Six-Pet').style.display = hidden; 
  }
  else if (Titan.value == "3"){
      var style = this.value == "3" ? 'block' : 'none';
      var hidden = 'none';
      document.getElementById('One-Pet').style.display = style;
      document.getElementById('Two-Pet').style.display = style;
      document.getElementById('Three-Pet').style.display = style;
      document.getElementById('Four-Pet').style.display = hidden;
      document.getElementById('Five-Pet').style.display = hidden;
      document.getElementById('Six-Pet').style.display = hidden; 
  }
  else if (Titan.value == "4"){
      var style = this.value == "4" ? 'block' : 'none';
      var hidden = 'none';
      document.getElementById('One-Pet').style.display = style;
      document.getElementById('Two-Pet').style.display = style;
      document.getElementById('Three-Pet').style.display = style;
      document.getElementById('Four-Pet').style.display = style;
      document.getElementById('Five-Pet').style.display = hidden;
      document.getElementById('Six-Pet').style.display = hidden; 
  }
  else if (Titan.value == "5"){
      var style = this.value == "5" ? 'block' : 'none';
      var hidden = 'none';
      document.getElementById('One-Pet').style.display = style;
      document.getElementById('Two-Pet').style.display = style;
      document.getElementById('Three-Pet').style.display = style;
      document.getElementById('Four-Pet').style.display = style;
      document.getElementById('Five-Pet').style.display = style;
      document.getElementById('Six-Pet').style.display = hidden; 
  }
  else if (Titan.value == "6"){
      var style = this.value == "6" ? 'block' : 'none';
      document.getElementById('One-Pet').style.display = style;
      document.getElementById('Two-Pet').style.display = style;
      document.getElementById('Three-Pet').style.display = style;
      document.getElementById('Four-Pet').style.display = style;
      document.getElementById('Five-Pet').style.display = style;
      document.getElementById('Six-Pet').style.display = style;        
  }

};

function NumPetFunc() {
    let Pnum = document.getElementById('NumPets')

    if (Pnum.value == "1"){
        var hidden = 'none';
        document.getElementById('PetTwo').style.display = hidden;
        document.getElementById('PetThree').style.display = hidden;
        document.getElementById('PetFour').style.display = hidden;
        document.getElementById('PetFive').style.display = hidden;
        document.getElementById('PetSix').style.display = hidden;
    }
    else if (Pnum.value == "2"){
        var style = this.value == "2" ? 'block' : 'none';
        var hidden = 'none';
        document.getElementById('PetTwo').style.display = style;
        document.getElementById('PetThree').style.display = hidden;
        document.getElementById('PetFour').style.display = hidden;
        document.getElementById('PetFive').style.display = hidden;
        document.getElementById('PetSix').style.display = hidden;
    }
    else if (Pnum.value == "3"){
        var style = this.value == "3" ? 'block' : 'none';
        var hidden = 'none';
        document.getElementById('PetTwo').style.display = style;
        document.getElementById('PetThree').style.display = style;
        document.getElementById('PetFour').style.display = hidden;
        document.getElementById('PetFive').style.display = hidden;
        document.getElementById('PetSix').style.display = hidden;
    }
    else if (Pnum.value == "4"){
        var style = this.value == "4" ? 'block' : 'none';
        var hidden = 'none';
        document.getElementById('PetTwo').style.display = style;
        document.getElementById('PetThree').style.display = style;
        document.getElementById('PetFour').style.display = style;
        document.getElementById('PetFive').style.display = hidden;
        document.getElementById('PetSix').style.display = hidden;
    }
    else if (Pnum.value == "5"){
        var style = this.value == "5" ? 'block' : 'none';
        var hidden = 'none';
        document.getElementById('PetTwo').style.display = style;
        document.getElementById('PetThree').style.display = style;
        document.getElementById('PetFour').style.display = style;
        document.getElementById('PetFive').style.display = style;
        document.getElementById('PetSix').style.display = hidden;
    }
    else if (Pnum.value == "6"){
        var style = this.value == "6" ? 'block' : 'none';
        document.getElementById('PetTwo').style.display = style;
        document.getElementById('PetThree').style.display = style;
        document.getElementById('PetFour').style.display = style;
        document.getElementById('PetFive').style.display = style;
        document.getElementById('PetSix').style.display = style;
    }

};

$('.wp-btn').click(function(){
    $('nav ul .wp-show').toggleClass("show");
    $('nav ul .first').toggleClass("rotate");
});
$('.bill-btn').click(function(){
  $('nav ul .bill-show').toggleClass("show1");
  $('nav ul .second').toggleClass("rotate");
});
$('.greeting-btn').click(function(){
  $('nav ul .greeting-show').toggleClass("show2");
  $('nav ul .third').toggleClass("rotate");
});
$('.cxl-btn').click(function(){
  $('nav ul .cxl-show').toggleClass("show3");
  $('nav ul .fourth').toggleClass("rotate");
});
$('.Web-btn').click(function(){
  $('nav ul .Web-show').toggleClass("show4");
  $('nav ul .fifth').toggleClass("rotate");
});
$('.App-btn').click(function(){
  $('nav ul .App-show').toggleClass("show5");
  $('nav ul .sixth').toggleClass("rotate");
});
$('nav ul li').click(function(){
  $(this).addClass("active").siblings().removeClass("active");
});



function openCity(evt, cityName) {
    var i, tabcontent, tablinks;
    tabcontent = document.getElementsByClassName("tabcontent");
    for (i = 0; i < tabcontent.length; i++) {
      tabcontent[i].style.display = "none";
      tabcontent[i].style.width = '1280px';
    }
    tablinks = document.getElementsByClassName("tablinks");
    for (i = 0; i < tablinks.length; i++) {
      tablinks[i].className = tablinks[i].className.replace(" active", "");
    }
    document.getElementById(cityName).style.display = "block";
    evt.currentTarget.className += " active";
  }
  
  // Get the element with id="defaultOpen" and click on it
  document.getElementById("defaultOpen").click();
  
  function mainlist(evt, cityName) {
    var i, tablinks, mainlinks;
    tablinks = document.getElementsByClassName("mainlinks");
    for (i = 0; i < tablinks.length; i++) {
      tablinks[i].style.display = "none";
    }
    mainlinks = document.getElementsByClassName("mainlinks");
    for (i = 0; i < mainlinks.length; i++) {
      mainlinks[i].className = mainlinks[i].className.replace(" active", "");
    }
    document.getElementById(cityName).style.display = "block";
    evt.currentTarget.className += " active";
  }
  
  // Get the element with id="defaultOpen" and click on it
  document.getElementById("defaultOpen").click();

  function copyToClipboard(element) {
    var $temp = $("<input>");
    $("body").append($temp);
    $temp.val($(element).text()).select();
    document.execCommand("copy");
    $temp.remove();
  }

  function copyparaToClipboard(element) {
    var $temp = $("<textarea>");
    var brRegex = /<br\s*[\/]?>/gi;
    $("body").append($temp);
    $temp.val($(element).html().replace(brRegex, "\r\n")).select();
    document.execCommand("copy");
    $temp.remove();
  }

  




  const insertcc = document.querySelector('#test');
  insertcc.addEventListener('click', () => {
    const subjectcc = document.querySelector('#NoteOutput');
    subjectcc.insertAdjacentHTML("beforeend" , '- edu on updating WP CC online');
  });

  const WPUCC = document.querySelector('#WPCCU');
  WPUCC.addEventListener('click', () => {
    const WPUCCn = document.querySelector('#NoteOutput');
    WPUCCn.insertAdjacentHTML("beforeend" , '- edu on updating WP CC online');
  });

  const IncPrice = document.querySelector('#OctPrice');
  IncPrice.addEventListener('click', () => {
    const subjectcc = document.querySelector('#NoteOutput');
    subjectcc.insertAdjacentHTML("beforeend" , '- edu on Jan price increase ');
  });

  const COFnotWP = document.querySelector('#COFWP');
  COFnotWP.addEventListener('click', () => {
    const subjectcof = document.querySelector('#NoteOutput');
    subjectcof.insertAdjacentHTML("beforeend" , '- cl updated COF instead of WPCC - edu how to update WPCC ');
  });

  const COF = document.querySelector('#COFCC');
  COF.addEventListener('click', () => {
    const subjectCOF = document.querySelector('#NoteOutput');
    subjectCOF.insertAdjacentHTML("beforeend" , '- edu how to update COF ');
  });

  const money = document.querySelector('#manualPymt');
  money.addEventListener('click', () => {
    const subjectmoney = document.querySelector('#NoteOutput');
    subjectmoney.insertAdjacentHTML("beforeend" , '- edu how to make pymt online ');
  });
  
  const BkAcct = document.querySelector('#Checkingnote');
  BkAcct.addEventListener('click', () => {
    const Subcheckchecking = document.querySelector('#NoteOutput');
    Subcheckchecking.insertAdjacentHTML("beforeend" , '- edu how to update Checking Acct info ');
  });

  const costexpl = document.querySelector('#costex');
  costexpl.addEventListener('click', () => {
    const subjectcostexpl = document.querySelector('#NoteOutput');
    subjectcostexpl.insertAdjacentHTML("beforeend" , '- referred to hspt for pricing ');
  });

  const DAC = document.querySelector('#DACbtn');
  DAC.addEventListener('click', () => {
    const DACn = document.querySelector('#NoteOutput');
    DACn.insertAdjacentHTML("beforeend" , '- edu on DAC ');
  });

  const DAClink = document.querySelector('#DAClinkbtn');
  DAClink.addEventListener('click', () => {
    const DAClinkn = document.querySelector('#NoteOutput');
    DAClinkn.insertAdjacentHTML("beforeend" , '- Provided Weblink to review Adult Dog Plans ');
  });

  const CAClink = document.querySelector('#CAClinkbtn');
  CAClink.addEventListener('click', () => {
    const CAClinkn = document.querySelector('#NoteOutput');
    CAClinkn.insertAdjacentHTML("beforeend" , '- Provided Weblink to review Adult Cat Plans ');
  });

  const PEClink = document.querySelector('#PEClinkbtn');
  PEClink.addEventListener('click', () => {
    const PEClinkn = document.querySelector('#NoteOutput');
    PEClinkn.insertAdjacentHTML("beforeend" , '- Provided Weblink to review Puppy Plans ');
  });

  const KEClink = document.querySelector('#KEClinkbtn');
  KEClink.addEventListener('click', () => {
    const KEClinkn = document.querySelector('#NoteOutput');
    KEClinkn.insertAdjacentHTML("beforeend" , '- Provided Weblink to review Kitten Plans ');
  });
  
  const GenPlan = document.querySelector('#GenPlanlinkbtn');
  GenPlan.addEventListener('click', () => {
    const GenPlann = document.querySelector('#NoteOutput');
    GenPlann.insertAdjacentHTML("beforeend" , '- Provided Weblink to review OWP ');
  });

  const DACP = document.querySelector('#DACPbtn');
  DACP.addEventListener('click', () => {
    const DACPn = document.querySelector('#NoteOutput');
    DACPn.insertAdjacentHTML("beforeend" , '- edu on DACP ');
  });

  const DSC = document.querySelector('#DSCbtn');
  DSC.addEventListener('click', () => {
    const DSCn = document.querySelector('#NoteOutput');
    DSCn.insertAdjacentHTML("beforeend" , '- edu on DSC ');
  });

  const CAC = document.querySelector('#CACbtn');
  CAC.addEventListener('click', () => {
    const CACn = document.querySelector('#NoteOutput');
    CACn.insertAdjacentHTML("beforeend" , '- edu on CAC ');
  });

  const CACP = document.querySelector('#CACPbtn');
  CACP.addEventListener('click', () => {
    const CACPn = document.querySelector('#NoteOutput');
    CACPn.insertAdjacentHTML("beforeend" , '- edu on CACP ');
  });

  const CSC = document.querySelector('#CSCbtn');
  CSC.addEventListener('click', () => {
    const CSCn = document.querySelector('#NoteOutput');
    CSCn.insertAdjacentHTML("beforeend" , '- edu on CSC ');
  });

  const PEC = document.querySelector('#PECbtn');
  PEC.addEventListener('click', () => {
    const PECn = document.querySelector('#NoteOutput');
    PECn.insertAdjacentHTML("beforeend" , '- edu on PEC ');
  });

  const PECP = document.querySelector('#PECPbtn');
  PECP.addEventListener('click', () => {
    const PECPn = document.querySelector('#NoteOutput');
    PECPn.insertAdjacentHTML("beforeend" , '- edu on PECP ');
  });

  const KEC = document.querySelector('#KECbtn');
  KEC.addEventListener('click', () => {
    const KECn = document.querySelector('#NoteOutput');
    KECn.insertAdjacentHTML("beforeend" , '- edu on KEC ');
  });

  const KECP = document.querySelector('#KECPbtn');
  KECP.addEventListener('click', () => {
    const KECPn = document.querySelector('#NoteOutput');
    KECPn.insertAdjacentHTML("beforeend" , '- edu on KECP ');
  });

  const BillInvo = document.querySelector('#BillInvoicebtn');
  BillInvo.addEventListener('click', () => {
    const BillInvon = document.querySelector('#NoteOutput');
    BillInvon.insertAdjacentHTML("beforeend" , '- edu on finding payment history online ');
  });

  const InvoiceBillingnotes = document.querySelector('#Invoicebillbtn');
  InvoiceBillingnotes.addEventListener('click', () => {
    const InvoiceBillingnotesn = document.querySelector('#NoteOutput');
    InvoiceBillingnotesn.insertAdjacentHTML("beforeend" , '- edu on finding invoices online ');
  });

  const Microchipinfo = document.querySelector('#Microchipinfobtn');
  Microchipinfo.addEventListener('click', () => {
    const Microchipinfon = document.querySelector('#NoteOutput');
    Microchipinfon.insertAdjacentHTML("beforeend" , '- referred to HomeAgain to update Microchip info ');
  });

  const PersInfo = document.querySelector('#PersInfobtn');
  PersInfo.addEventListener('click', () => {
    const PersInfon = document.querySelector('#NoteOutput');
    PersInfon.insertAdjacentHTML("beforeend" , '- edu how to update personal info online ');
  });

  const SettoDNR = document.querySelector('#SettoDNRbtn');
  SettoDNR.addEventListener('click', () => {
    const SettoDNRn = document.querySelector('#NoteOutput');
    SettoDNRn.insertAdjacentHTML("beforeend" , '- edu how to set to DNR online ');
  });

  const OldOrder = document.querySelector('#OldOrderbtn');
  OldOrder.addEventListener('click', () => {
    const OldOrdern = document.querySelector('#NoteOutput');
    OldOrdern.insertAdjacentHTML("beforeend" , '- referred to eComm for online orders ');
  });

  const NewOrder = document.querySelector('#NewOrderbtn');
  NewOrder.addEventListener('click', () => {
    const NewOrdern = document.querySelector('#NoteOutput');
    NewOrdern.insertAdjacentHTML("beforeend" , '- edu how to place order on BanfieldShop online ');
  });

  const Enrolling = document.querySelector('#Enrollingbtn');
  Enrolling.addEventListener('click', () => {
    const Enrollingn = document.querySelector('#NoteOutput');
    Enrollingn.insertAdjacentHTML("beforeend" , '- edu how to enroll in OWP online ');
  });

  const Schedulingapptbtn = document.querySelector('#Schedulingapptbtn');
  Schedulingapptbtn.addEventListener('click', () => {
    const Schedulingapptbtnn = document.querySelector('#NoteOutput');
    Schedulingapptbtnn.insertAdjacentHTML("beforeend" , '- edu how to schedule appointment ');
  });

  const Reschcxlapptbtn = document.querySelector('#Reschcxlapptbtn');
  Reschcxlapptbtn.addEventListener('click', () => {
    const Reschcxlapptbtnn = document.querySelector('#NoteOutput');
    Reschcxlapptbtnn.insertAdjacentHTML("beforeend" , '- edu how to adjust a scheduled appointment online ');
  });

  const Invoicebill1btn = document.querySelector('#Invoicebill1btn');
  Invoicebill1btn.addEventListener('click', () => {
    const Invoicebill1btnn = document.querySelector('#NoteOutput');
    Invoicebill1btnn.insertAdjacentHTML("beforeend" , '- edu how to review invoices online ');
  });

  const Vaxbtn = document.querySelector('#Vaxbtn');
  Vaxbtn.addEventListener('click', () => {
    const Vaxbtnn = document.querySelector('#NoteOutput');
    Vaxbtnn.insertAdjacentHTML("beforeend" , '- edu how to find Vax records ');
  });

  const DNAWisdombtn = document.querySelector('#DNAWisdombtn');
  DNAWisdombtn.addEventListener('click', () => {
    const DNAWisdombtnn = document.querySelector('#NoteOutput');
    DNAWisdombtnn.insertAdjacentHTML("beforeend" , '- edu where to find Wisdom Panel Results online ');
  });

  const RegOnlinebtn = document.querySelector('#RegOnlinebtn');
  RegOnlinebtn.addEventListener('click', () => {
    const RegOnlinebtnn = document.querySelector('#NoteOutput');
    RegOnlinebtnn.insertAdjacentHTML("beforeend" , '- edu how to register new online acct ');
  });

  const PWResetbtn = document.querySelector('#PWResetbtn');
  PWResetbtn.addEventListener('click', () => {
    const PWResetbtnn = document.querySelector('#NoteOutput');
    PWResetbtnn.insertAdjacentHTML("beforeend" , '- edu how to reset PW online ');
  });

  const PWResetWbtn = document.querySelector('#PWResetWbtn');
  PWResetWbtn.addEventListener('click', () => {
    const PWResetWbtnn = document.querySelector('#NoteOutput');
    PWResetWbtnn.insertAdjacentHTML("beforeend" , '- edu how to reset PW online ');
  });

  const Scrshotbtn = document.querySelector('#Scrshotbtn');
  Scrshotbtn.addEventListener('click', () => {
    const Scrshotbtnn = document.querySelector('#NoteOutput');
    Scrshotbtnn.insertAdjacentHTML("beforeend" , '- adv to send in screenshot of missing information with as much information to review the problem ');
  });

  const HiddenPetbtn = document.querySelector('#HiddenPetbtn');
  HiddenPetbtn.addEventListener('click', () => {
    const HiddenPetbtnn = document.querySelector('#NoteOutput');
    HiddenPetbtnn.insertAdjacentHTML("beforeend" , '- edu how to hide pet online ');
  });

  const ShowPetsbtn = document.querySelector('#ShowPetsbtn');
  ShowPetsbtn.addEventListener('click', () => {
    const ShowPetsbtnn = document.querySelector('#NoteOutput');
    ShowPetsbtnn.insertAdjacentHTML("beforeend" , '- edu how to unhide pet online ');
  });

  const APPOTPbtn = document.querySelector('#APPOTPbtn');
  APPOTPbtn.addEventListener('click', () => {
    const APPOTPbtnn = document.querySelector('#NoteOutput');
    APPOTPbtnn.insertAdjacentHTML("beforeend" , '- edu how to make One-Time Pymt on App ');
  });

  const APPSCHbtn = document.querySelector('#APPSCHbtn');
  APPSCHbtn.addEventListener('click', () => {
    const APPSCHbtnn = document.querySelector('#NoteOutput');
    APPSCHbtnn.insertAdjacentHTML("beforeend" , '- edu how to schedule appt on App ');
  });

  const APPCXLAPPTbtn = document.querySelector('#APPCXLAPPTbtn');
  APPCXLAPPTbtn.addEventListener('click', () => {
    const APPCXLAPPTbtnn = document.querySelector('#NoteOutput');
    APPCXLAPPTbtnn.insertAdjacentHTML("beforeend" , '- edu how to adjust scheduled appt on App ');
  });

  const APPVETCHATbtn = document.querySelector('#APPVETCHATbtn');
  APPVETCHATbtn.addEventListener('click', () => {
    const APPVETCHATbtnn = document.querySelector('#NoteOutput');
    APPVETCHATbtnn.insertAdjacentHTML("beforeend" , '- edu how to contact VetChat on App ');
  });

  const APPPicbtn = document.querySelector('#APPPicbtn');
  APPPicbtn.addEventListener('click', () => {
    const APPPicbtnn = document.querySelector('#NoteOutput');
    APPPicbtnn.insertAdjacentHTML("beforeend" , '- edu how to change pet picture on App ');
  });

  const AppBkinfobtn = document.querySelector('#AppBkinfobtn');
  AppBkinfobtn.addEventListener('click', () => {
    const AppBkinfobtnn = document.querySelector('#NoteOutput');
    AppBkinfobtnn.insertAdjacentHTML("beforeend" , '- edu how to update WP CC on App ');
  });

  const APPCOFinfobtn = document.querySelector('#APPCOFinfobtn');
  APPCOFinfobtn.addEventListener('click', () => {
    const APPCOFinfobtnn = document.querySelector('#NoteOutput');
    APPCOFinfobtnn.insertAdjacentHTML("beforeend" , '- edu how to update COF CC on App ');
  });

  const APPPymHstybtn = document.querySelector('#APPPymHstybtn');
  APPPymHstybtn.addEventListener('click', () => {
    const APPPymHstybtnn = document.querySelector('#NoteOutput');
    APPPymHstybtnn.insertAdjacentHTML("beforeend" , '- edu how to review pymt history on App ');
  });

  const APPInvoicebtn = document.querySelector('#APPInvoicebtn');
  APPInvoicebtn.addEventListener('click', () => {
    const APPInvoicebtnn = document.querySelector('#NoteOutput');
    APPInvoicebtnn.insertAdjacentHTML("beforeend" , '- edu how to find Invoices on App ');
  });

  const APPVaxbtn = document.querySelector('#APPVaxbtn');
  APPVaxbtn.addEventListener('click', () => {
    const APPVaxbtnn = document.querySelector('#NoteOutput');
    APPVaxbtnn.insertAdjacentHTML("beforeend" , '- edu how to Vax records on App ');
  });

  const APPMicrobtn = document.querySelector('#APPMicrobtn');
  APPMicrobtn.addEventListener('click', () => {
    const APPMicrobtnn = document.querySelector('#NoteOutput');
    APPMicrobtnn.insertAdjacentHTML("beforeend" , '- edu where to find rabies/microchip information on App ');
  });

  const AppPetHidebtn = document.querySelector('#AppPetHidebtn');
  AppPetHidebtn.addEventListener('click', () => {
    const AppPetHidebtnn = document.querySelector('#NoteOutput');
    AppPetHidebtnn.insertAdjacentHTML("beforeend" , '- edu how to show/hide pets on App ');
  });

  const TxtTO2btn = document.querySelector('#TxtTO2btn');
  TxtTO2btn.addEventListener('click', () => {
    const TxtTO2btnn = document.querySelector('#NoteOutput');
    TxtTO2btnn.insertAdjacentHTML("beforeend" , '- sent 2-miunte TO Warning ');
  });

  const TxtTO3btn = document.querySelector('#TxtTO3btn');
  TxtTO3btn.addEventListener('click', () => {
    const TxtTO3btnn = document.querySelector('#NoteOutput');
    TxtTO3btnn.insertAdjacentHTML("beforeend" , '- sent 3-miunte TO Ending ');
  });

  const OptOutOptionbtn = document.querySelector('#OptOutOptionbtn');
  OptOutOptionbtn.addEventListener('click', () => {
    const OptOutOptionbtnn = document.querySelector('#NoteOutput');
    OptOutOptionbtnn.insertAdjacentHTML("beforeend" , '- sent Opt-Out Message - sent RD email ');
  });

  const TextCallInbtn = document.querySelector('#TextCallInbtn');
  TextCallInbtn.addEventListener('click', () => {
    const TextCallInbtnn = document.querySelector('#NoteOutput');
    TextCallInbtnn.insertAdjacentHTML("beforeend" , '- adv unable to call in CHAT - edu how to call in if needed ');
  });

  const RNSCertbtn = document.querySelector('#RNSCertbtn');
  RNSCertbtn.addEventListener('click', () => {
    const RNSCertbtnn = document.querySelector('#NoteOutput');
    RNSCertbtnn.insertAdjacentHTML("beforeend" , '- edu on options for Certification request ');
  });

  const EmailReqbtn = document.querySelector('#EmailReqbtn');
  EmailReqbtn.addEventListener('click', () => {
    const EmailReqbtnn = document.querySelector('#NoteOutput');
    EmailReqbtnn.insertAdjacentHTML("beforeend" , '- sent RD request for document to be emailed ');
  });

  const WNCbtn = document.querySelector('#WNCbtn');
  WNCbtn.addEventListener('click', () => {
    const WNCbtnn = document.querySelector('#NoteOutput');
    WNCbtnn.insertAdjacentHTML("beforeend" , '- adv we dont reach out for PDB until plan is on Hold ');
  });

  const RemoveCCArguebtn = document.querySelector('#RemoveCCArguebtn');
  RemoveCCArguebtn.addEventListener('click', () => {
    const RemoveCCArguebtnn = document.querySelector('#NoteOutput');
    RemoveCCArguebtnn.insertAdjacentHTML("beforeend" , '- edu unable to remove WP CC, only replace ');
  });

  const RenewalArguebtn = document.querySelector('#RenewalArguebtn');
  RenewalArguebtn.addEventListener('click', () => {
    const RenewalArguebtnn = document.querySelector('#NoteOutput');
    RenewalArguebtnn.insertAdjacentHTML("beforeend" , '- edu on Auto-Renwal ');
  });

  const PetInfoBtn = document.querySelector('#PetInfoBtn');
  PetInfoBtn.addEventListener('click', () => {
    const PetInfoBtnn = document.querySelector('#NoteOutput');
    PetInfoBtnn.insertAdjacentHTML("beforeend" , '- edu how to update pet information at hspt ');
  });

  const PersonalInfoBtn = document.querySelector('#PersonalInfoBtn');
  PersonalInfoBtn.addEventListener('click', () => {
    const PersonalInfoBtnn = document.querySelector('#NoteOutput');
    PersonalInfoBtnn.insertAdjacentHTML("beforeend" , '- edu how to update name at hspt with Valid ID ');
  });

  const BillingInfobtn = document.querySelector('#BillingInfobtn');
  BillingInfobtn.addEventListener('click', () => {
    const BillingInfobtnn = document.querySelector('#NoteOutput');
    BillingInfobtnn.insertAdjacentHTML("beforeend" , '- edu how to update billing information online ');
  });

  const Invoicebill2btn = document.querySelector('#Invoicebill2btn');
  Invoicebill2btn.addEventListener('click', () => {
    const Invoicebill2btnn = document.querySelector('#NoteOutput');
    Invoicebill2btnn.insertAdjacentHTML("beforeend" , '- edu how to find invoices online ');
  });

  const Vax1btn = document.querySelector('#Vax1btn');
  Vax1btn.addEventListener('click', () => {
    const Vax1btnn = document.querySelector('#NoteOutput');
    Vax1btnn.insertAdjacentHTML("beforeend" , '- edu how to find vax records online ');
  });

  const DNAWisdom2btn = document.querySelector('#DNAWisdom2btn');
  DNAWisdom2btn.addEventListener('click', () => {
    const DNAWisdom2btnn = document.querySelector('#NoteOutput');
    DNAWisdom2btnn.insertAdjacentHTML("beforeend" , '- edu how to find DNA results ');
  });




 



function QRking() {

  let PName = document.getElementById("PetOne1").value;
  let PName2 = document.getElementById("PetTwo2").value;
  let PName3 = document.getElementById("PetThree3").value;
  let PName4 = document.getElementById("PetFour4").value;
  let PName5 = document.getElementById("PetFive5").value;
  let PName6 = document.getElementById("PetSix6").value;

  let Namebox = [];

  let namelooptestqr = {NL:[
      {Name: PName},
      {Name: PName2},
      {Name: PName3},
      {Name: PName4},
      {Name: PName5},
      {Name: PName6}
    ]}
  
  let qrtime = namelooptestqr['NL'];
  for(let i=0, len=qrtime.length; i<len; i++){
  //    console.log(qrtime[i]);
      Namebox.push(qrtime[i].Name)
  //    console.log(qrtime[i].Name);
  console.log(qrtime[i].Name)
  }
  
  var filtername = Namebox.filter(function(x) {
    return x !== "";
  });

    const stnotes = document.querySelector('#NoteOutput');
    const clientname = document.getElementById("Clientname").value;
    const calltype = document.getElementById("chattext").value;
    stnotes.insertAdjacentHTML("beforeend", ""+calltype+": "+clientname+ " ci ");

console.log(filtername);

// Var's below for name population must be lowercase
var ppselect = document.getElementById("passedpetdd");
var udpets = document.getElementById("UGDGpets");
var meep1 = document.getElementById("MEEPpet1");
var meep2 = document.getElementById("MEEPpet2");
var meep3 = document.getElementById("MEEPpet3");
var meep4 = document.getElementById("MEEPpet4");
var meep5 = document.getElementById("MEEPpet5");
var meep6 = document.getElementById("MEEPpet6");
var remeddd = document.getElementById("RMNames");
var billdd = document.getElementById("BillExplainDD");
var pdbn = document.getElementById("PDBnames");

for(var i = 0; i < filtername.length; i++) {
  var opt = filtername[i];
  var el = document.createElement("option");
  el.textContent = opt;
  el.value = opt;
  ppselect.appendChild(el);
}
for(var i = 0; i < filtername.length; i++) {
  var opt = filtername[i];
  var el = document.createElement("option");
  el.textContent = opt;
  el.value = opt;
  udpets.appendChild(el);
}
for(var i = 0; i < filtername.length; i++) {
  var opt = filtername[i];
  var el = document.createElement("option");
  el.textContent = opt;
  el.value = opt;
  pdbn.appendChild(el);
}
for(var i = 0; i < filtername.length; i++) {
  var opt = filtername[i];
  var el = document.createElement("option");
  el.textContent = opt;
  el.value = opt;
  billdd.appendChild(el);
}
for(var i = 0; i < filtername.length; i++) {
  var opt = filtername[i];
  var el = document.createElement("option");
  el.textContent = opt;
  el.value = opt;
  remeddd.appendChild(el);
}
for(var i = 0; i < filtername.length; i++) {
  var opt = filtername[i];
  var el = document.createElement("option");
  el.textContent = opt;
  el.value = opt;
  meep1.appendChild(el);
}
for(var i = 0; i < filtername.length; i++) {
  var opt = filtername[i];
  var el = document.createElement("option");
  el.textContent = opt;
  el.value = opt;
  meep2.appendChild(el);
}
for(var i = 0; i < filtername.length; i++) {
  var opt = filtername[i];
  var el = document.createElement("option");
  el.textContent = opt;
  el.value = opt;
  meep3.appendChild(el);
}
for(var i = 0; i < filtername.length; i++) {
  var opt = filtername[i];
  var el = document.createElement("option");
  el.textContent = opt;
  el.value = opt;
  meep4.appendChild(el);
}
for(var i = 0; i < filtername.length; i++) {
  var opt = filtername[i];
  var el = document.createElement("option");
  el.textContent = opt;
  el.value = opt;
  meep5.appendChild(el);
}
for(var i = 0; i < filtername.length; i++) {
  var opt = filtername[i];
  var el = document.createElement("option");
  el.textContent = opt;
  el.value = opt;
  meep6.appendChild(el);
}
}

var PDB = document.getElementById('PDBnames').value;
var PDBamt = document.getElementById('PDBamt').value;
var PDBdate = document.getElementById('PDBdate').value;

  let PDBnote = "Example: Looking at  PETNAME's plan, I can see the plan is currently past due for $AMT for the missed installment on DATE";
  console.log(PDB)

  document.getElementById("PDBnote").innerText = PDBnote;

function PDBnotes(){
  let OnHold = document.getElementById('OHdate').value;
  console.log(OnHold)
  if (OnHold == 'Yes'){
    var PDB = document.getElementById('PDBnames').value;
    var PDBamt = document.getElementById('PDBamt').value;
    var PDBdate = document.getElementById('PDBdate').value;
    var todaypdb = new Date(PDBdate);{
      var dd = (todaypdb.getDate()+1);
      var mm = (todaypdb.getMonth()+1);
      var yyyy = todaypdb.getFullYear();
  
      todaypdb = mm+'/'+dd+'/'+yyyy;}
  
      let PDBnote = "Looking at "+PDB+"'s plan, I can see the plan is currently on Hold for the past due balance of $"+PDBamt+" for the unsuccessful installments on "+todaypdb+". Please keep in mind there is a 120 day grace period from the Hold Date to bring the balance current to prevent the plan from defaulting into collections for non-payment.";
      document.getElementById("PDBnote").innerText = PDBnote;
      console.log(todaypdb)
      console.log(dd)

      const PDBbtn = document.querySelector('#PDBbtn');
      PDBbtn.addEventListener('click', () => {
        var PDB = document.getElementById('PDBnames').value;
        var PDBamt = document.getElementById('PDBamt').value;
          const PDBbtnn = document.querySelector('#NoteOutput');
          PDBbtnn.insertAdjacentHTML("beforeend" , '- adv '+PDB+' plan is on Hold for PDB $'+PDBamt+' for missed installment on '+todaypdb+' ');
      });
  } else {
    var PDB = document.getElementById('PDBnames').value;
    var PDBamt = document.getElementById('PDBamt').value;
    var PDBdate = document.getElementById('PDBdate').value;
    var todaypdb = new Date(PDBdate);{
      var dd = (todaypdb.getDate()+1);
      var mm = (todaypdb.getMonth()+1);
      var yyyy = todaypdb.getFullYear();
  
      todaypdb = mm+'/'+dd+'/'+yyyy;}
  
      let PDBnote = "Looking at "+PDB+"'s plan, I can see the plan is currently past due for $"+PDBamt+" for the missed installment on "+todaypdb+"";
      document.getElementById("PDBnote").innerText = PDBnote;
      console.log(todaypdb)
      console.log(dd)

      const PDBbtn = document.querySelector('#PDBbtn');
      PDBbtn.addEventListener('click', () => {
        var PDB = document.getElementById('PDBnames').value;
        var PDBamt = document.getElementById('PDBamt').value;
          const PDBbtnn = document.querySelector('#NoteOutput');
          PDBbtnn.insertAdjacentHTML("beforeend" , '- adv '+PDB+' PDB $'+PDBamt+' for missed installment on '+todaypdb+' ');
      });
  }}

  let BillPlanExplain = "Looking at  PETNAME's plan, I can see the plan is currently past due for $AMT for the missed installment on DATE";
  

  document.getElementById("BillPlanExplain").innerText = BillPlanExplain;

function BGENExNotes(){
    var Names = document.getElementById('PDBnames').value;
    var AMTS = document.getElementById('bgenamtinput').value;
    var DATES = document.getElementById('BGenBKdate').value;


      let BillPlanExplain = "Looking at "+Names+"'s plan, I can see they are set to draft $"+AMTS+" on the "+DATES+"th of each month.";
      document.getElementById("BillPlanExplain").innerText = BillPlanExplain;
    }

    const BillPlanExplainbtn = document.querySelector('#BillPlanExplainbtn');
    BillPlanExplainbtn.addEventListener('click', () => {
      var Names = document.getElementById('BillExplainDD').value;
      var AMTS = document.getElementById('bgenamtinput').value;
      var DATES = document.getElementById('BGenBKdate').value;
        const BillPlanExplainbtnn = document.querySelector('#NoteOutput');
        BillPlanExplainbtnn.insertAdjacentHTML("beforeend" , '- edu '+Names+'s BK is '+DATES+'th & install amt of $'+AMTS+' ');
    });
  
  
  var PPC = document.getElementById('passedpetdd').value;

  let PPCnote = "We are very sorry to hear about the loss of your beloved pet. Our thoughts are with you during this difficult time, please accept our deepest condolences.";
  console.log(PPC)

  document.getElementById("ppassed-chatp").innerText = PPCnote;



function DispoEnding(){
  var Dispodd = document.getElementById('DispoBox').value;
  console.log(Dispodd)
  if (Dispodd == 'NoChange') {

  const subjectaddingdisposition = document.querySelector('#NoteOutput');
  subjectaddingdisposition.insertAdjacentHTML('beforeend' , '- no changes made');

  } else if (Dispodd == 'TimedOut') {


  const subjectaddingdisposition = document.querySelector('#NoteOutput');
  subjectaddingdisposition.insertAdjacentHTML('beforeend' , '- cl timed out');
  } else if (Dispodd == 'TimeoutNoChange') {


  const subjectaddingdisposition = document.querySelector('#NoteOutput');
  subjectaddingdisposition.insertAdjacentHTML("beforeend" , '- cl timed out - no changes made');
  } else if (Dispodd == 'DNR') {


    const subjectaddingdisposition = document.querySelector('#NoteOutput');
    subjectaddingdisposition.insertAdjacentHTML("beforeend" , '- set to DNR');
  } else if (Dispodd == 'ADNR') {


  const subjectaddingdisposition = document.querySelector('#NoteOutput');
    subjectaddingdisposition.insertAdjacentHTML("beforeend" , '- already set to DNR - no changes made');
  } else if (Dispodd == 'CEC') {

    const subjectaddingdisposition = document.querySelector('#NoteOutput');
    subjectaddingdisposition.insertAdjacentHTML("beforeend" , '- cl ended chat ');
  } else if (Dispodd == 'CECNCM') {

    const subjectaddingdisposition = document.querySelector('#NoteOutput');
    subjectaddingdisposition.insertAdjacentHTML("beforeend" , '- cl ended chat - no changes made ');
  } else if (Dispodd == 'TTO') {

    const subjectaddingdisposition = document.querySelector('#NoteOutput');
    subjectaddingdisposition.insertAdjacentHTML("beforeend" , 'TEXT:  ci - timed out - no changes made');
  }
}

function Petpassed(){
  var PPC = document.getElementById('passedpetdd').value;
    let PPCnote = "We are very sorry to hear about the loss of your beloved "+PPC+". Our thoughts are with you during this difficult time, please accept our deepest condolences.";
    document.getElementById("ppassed-chatp").innerText = PPCnote;
  }

  const PPassed = document.querySelector('#PPassedbtn');
  PPassed.addEventListener('click', () => {
      const PPassedn = document.querySelector('#NoteOutput');
      PPassedn.insertAdjacentHTML("beforeend" , ' to cxl ');
  });

  var RSS = document.getElementById('BKdate').value;

  let RSSTest = "Please select Banking Day Above to Generate Note";

  document.getElementById("RSnote").innerText = RSSTest;


function RSdate(){
  var RSS = document.getElementById('BKdate').value;
  var today = new Date();{
    var dd = today.getDate();
    var mm = (today.getMonth()+1);
    var yyyy = today.getFullYear();

    today = mm+'/'+dd+'/'+yyyy;
    console.log(today)
  }

  if (dd < parseInt(RSS)){
    var mm = mm;
  } else {
    var mm = (mm+1);
  }

  console.log(mm)
  var BKRSOptions = {OptionList:[
    ['5','12', '19', '26'],
    ['12', '19', '26', '5'],
    ['19', '26', '5','12'],
    ['26', '5','12', '19']
  ]}

  let OPList = BKRSOptions['OptionList'];
  let filteredRSdate = OPList.filter((OPList) => {
    return OPList[0] == RSS;
  })


  let testtestloop = filteredRSdate;
  var finalfilterbk = testtestloop[0].filter(function(x) {
    return x <= parseInt(RSS);
    });
  
  
  var finalfilterft = testtestloop[0].filter(function(v) {
    return v > parseInt(RSS);
    });



  if (finalfilterft.length == 3){
    var opt1 = finalfilterbk[0];
    var opt2 = finalfilterft[0];
    var opt3 = finalfilterft[1];
    var opt4 = finalfilterft[2];

    let RSnote = "I can reschedule all the installments on "+mm+"/"+opt1+"/"+yyyy+" to either "+mm+"/"+opt2+", "+mm+"/"+opt3+", "+mm+"/"+opt4+", or a one time double payment on "+(mm+1)+"/"+opt1+". Which date works best?";
    document.getElementById("RSnote").innerText = RSnote;
  } else if (finalfilterft.length == 2){
    var opt1 = finalfilterbk[0];
    var opt2 = finalfilterft[0];
    var opt3 = finalfilterft[1];
    var opt4 = finalfilterbk[1];

    let RSnote = "I can reschedule all the installments on "+mm+"/"+opt1+"/"+yyyy+" to either "+mm+"/"+opt2+", "+mm+"/"+opt3+", "+(mm+1)+"/"+opt4+", or a one time double payment on "+(mm+1)+"/"+opt1+". Which date works best?";
    document.getElementById("RSnote").innerText = RSnote;
  } else if (finalfilterft.length == 1){
    var opt1 = finalfilterbk[0];
    var opt2 = finalfilterft[0];
    var opt3 = finalfilterbk[2];
    var opt4 = finalfilterbk[1];

    let RSnote = "I can reschedule all the installments on "+mm+"/"+opt1+"/"+yyyy+" to either "+mm+"/"+opt2+", "+(mm+1)+"/"+opt3+", "+(mm+1)+"/"+opt4+", or a one time double payment on "+(mm+1)+"/"+opt1+". Which date works best?";
    document.getElementById("RSnote").innerText = RSnote;
  } else if (finalfilterft.length == 0){
    var opt1 = finalfilterbk[0];
    var opt2 = finalfilterbk[1];
    var opt3 = finalfilterbk[2];
    var opt4 = finalfilterbk[3];

    let RSnote = "I can reschedule all the installments on "+mm+"/"+opt1+"/"+yyyy+" to either "+(mm+1)+"/"+opt2+", "+(mm+1)+"/"+opt3+", "+(mm+1)+"/"+opt4+", or a one time double payment on "+(mm+1)+"/"+opt1+". Which date works best?";
    document.getElementById('RSnote').innerHTML=RSnote
  }}

  const RSRS = document.querySelector('#RSbtn');
  RSRS.addEventListener('click', () => {
    var RSS = document.getElementById('BKdate').value;
    var today = new Date();{
      var dd = today.getDate();
      var mm = (today.getMonth()+1);
      var yyyy = today.getFullYear();
  
      today = mm+'/'+dd+'/'+yyyy;
      console.log(today)
    }
  
    if (dd < parseInt(RSS)){
      var mm = mm;
    } else {
      var mm = (mm+1);
    }
      const RSRSn = document.querySelector('#NoteOutput');
      RSRSn.insertAdjacentHTML("beforeend" , '- inq on RS installment on '+mm+'/'+RSS+'/'+yyyy+'');
  });


function UGDGbalowed(){
  let question = document.getElementById('ugdgbalowedquestion')

  if (question.value == "Yes"){
    var style = this.value == "Yes" ? 'block' : 'none';
    var hidden = 'none';
    document.getElementById('ugdgbalowedinput').style.display = style;
    document.getElementById('ugdgenddateinput').style.display = style;
} else if (question.value == "No"){
  var style = this.value == "No" ? 'block' : 'none';
  var hidden = 'none';
  document.getElementById('ugdgbalowedinput').style.display = hidden;
  document.getElementById('ugdgenddateinput').style.display = hidden;
} };

function UGDGform(){
  let UGDGname = document.getElementById('UGDGpets').value;
  let UDGDchoice = document.getElementById('UGDGoptions').value;
  let UGDGbalquestion = document.getElementById('ugdgbalowedquestion').value;
  let UDGDbal = document.getElementById('ugdgbalowed').value;
  let UDGDdate = document.getElementById('ugdgenddate').value;
  
  
  if (UDGDchoice == "Upgrade" && UGDGbalquestion == "Yes"){
    let UGDGnote = " I can help you with that. In order to upgrade a wellness plan in the middle of a plan year any medications already dispensed, and not yet paid for through instalments would need to be paid in full first, as upgrading creates a new 12 month agreement. Looking at the plan for "+UGDGname+" it appears there would be a balance of $"+UDGDbal+" to pay for the medication financed through your wellness plan. Would you like to pay that balance today to upgrade or would you prefer to set the plan to automatically renew to the higher plan level on "+UDGDdate+"?";

    document.getElementById('UGDGparttwo').style.display = '';

    document.getElementById('uddgresultsbody').innerText= UGDGnote;
  } else if (UDGDchoice == "Upgrade" && UGDGbalquestion == "No"){
    let UGDGnote = "There are two options when upgrading before renewal. First, I can submit a request for the upgrade, this does take 3 to 5 business days to be manually completed and take effect. Second, you can complete it at the hospital at your next scheduled appointment, where it can be completed the same day. Both options will start a new 12-month agreement on the day it's completed. Which option sounds best for you?";

    document.getElementById('UGDGparttwo').style.display = '';

    document.getElementById('uddgresultsbody').innerText= UGDGnote;
} else if (UDGDchoice == "Downgrade" && UGDGbalquestion == "Yes"){
  let UGDGnote = "In order to downgrade a wellness plan in the middle of a plan year, any services already used and not yet paid for through installments would need to be paid in full first, as downgrading creates a new 12-month agreement. Looking at the plan for "+UGDGname+" it appears there would be a balance of $"+UDGDbal+" to pay for the care received since the plan started. Would you like to pay that balance today to downgrade or would you prefer to set the plan to automatically renew to the lower plan level on "+UDGDdate+"?";

  document.getElementById('UGDGparttwo').style.display = '';

  document.getElementById('uddgresultsbody').innerText= UGDGnote;
} else {
  let UGDGnote = "There are two options when downgrading before renewal. First, I can submit a request for the downgrade, this does take 3 to 5 business days to be manually completed and take effect. Second, you can complete it at the hospital at your next scheduled appointment, where it can be completed the same day. Both options will start a new 12-month agreement on the day it's completed. Which option sounds best for you?";

  document.getElementById('UGDGparttwo').style.display = '';

  document.getElementById('uddgresultsbody').innerText= UGDGnote;
};

};

const UGDGcbn = document.querySelector('#UGDGCopyBtnNote');
UGDGcbn.addEventListener('click', () => {

    var UGDGname = document.getElementById('UGDGpets').value;
    var UDGDbal = document.getElementById('ugdgbalowed').value;
    var UDGDchoice = document.getElementById('UGDGoptions').value;
    var UGDGbalquestion = document.getElementById('ugdgbalowedquestion').value;
    var UDGDbal = document.getElementById('ugdgbalowed').value;
    var UDGDdate = document.getElementById('ugdgenddate').value;
    
    if (UDGDchoice == "Upgrade" && UGDGbalquestion == "Yes"){
      const UGDGcbnn = document.querySelector('#NoteOutput');
      UGDGcbnn.insertAdjacentHTML("beforeend" , '- adv  $'+UDGDbal+' for '+UGDGname+' to UG');
    } else if (UDGDchoice == "Upgrade" && UGDGbalquestion == "No"){
      const UGDGcbnn = document.querySelector('#NoteOutput');
      UGDGcbnn.insertAdjacentHTML("beforeend" , '- adv no cost for '+UGDGname+' to UG');
    } else if (UDGDchoice == "Downgrade" && UGDGbalquestion == "Yes"){
    const UGDGcbnn = document.querySelector('#NoteOutput');
    UGDGcbnn.insertAdjacentHTML("beforeend" , '- adv  $'+UDGDbal+' for '+UGDGname+' to DG');
  } else {
    const UGDGcbnn = document.querySelector('#NoteOutput');
      UGDGcbnn.insertAdjacentHTML("beforeend" , '- adv no cost for '+UGDGname+' to DG');
}})

const UGDGreso = document.querySelector('#UGDGhspt');
UGDGreso.addEventListener('click', () => {
  const UGDGreson = document.querySelector('#NoteOutput');
  UGDGreson.insertAdjacentHTML("beforeend" , '- cl will complete at hspt ');
});

const UGDGreso2 = document.querySelector('#UGDGus');
UGDGreso2.addEventListener('click', () => {
  const UGDGreso2n = document.querySelector('#NoteOutput');
  UGDGreso2n.insertAdjacentHTML("beforeend" , '- verified DOB - submit request - adv 3-5 business days to complete ');
});

document.getElementById("submit-button").addEventListener("click", buildServ);
document.getElementById("submit-button").addEventListener("click", unhide);

function unhide() {
  // get the clock
  var Meeper = document.getElementById('MEEPBottompart');

  // get the current value of the clock's display property
  var MeepSetting = Meeper.style.display;

  // also get the clock button, so we can change what it says

  // now toggle the clock and the button text, depending on current state
  if (MeepSetting == 'none') {
    // clock is visible. hide it
    Meeper.style.display = 'block';
    // change button text

  }
  else {

  }
}

const UnableWRPFbtn = document.querySelector('#UnableWRPFbtn');
UnableWRPFbtn.addEventListener('click', () => {
  const UnableWRPFbtnn = document.querySelector('#NoteOutput');

  let Status = document.getElementById("WROptions").value;
  let WRDate = document.getElementById("WRPFDate").value;

  var today = new Date(WRDate);{
    var dd = (today.getDate()+1);
    var mm = (today.getMonth()+1);
    var yyyy = today.getFullYear();

    var waiverefunddate = mm+'/'+dd+'/'+yyyy;
    console.log(waiverefunddate)
  }
  
  UnableWRPFbtnn.insertAdjacentHTML("beforeend" , '- adv unable to '+Status+' RPF due to OTC already used on '+waiverefunddate+' ');
});

function WaiveRPF() {
  let Status = document.getElementById("WROptions").value;
  let WRDate = document.getElementById("WRPFDate").value;

  var today = new Date(WRDate);{
    var dd = (today.getDate()+1);
    var mm = (today.getMonth()+1);
    var yyyy = today.getFullYear();

    var waiverefunddate = mm+'/'+dd+'/'+yyyy;
    console.log(waiverefunddate)
  }

  let WAIVENOTE = "Apologies. At this time I am unable to "+Status+" the current $20.00 reprocessing charge as it appears that courtesy was already extended to you on "+waiverefunddate+". We are only able to use one courtesy per account as we understand life can happen unexpectedly";

  document.getElementById("UnableWRPF").innerText = WAIVENOTE;
  
}

const WRRPFbtn = document.querySelector('#WRRPFbtn');
WRRPFbtn.addEventListener('click', () => {
  const WRRPFbtnn = document.querySelector('#NoteOutput');

  let Status = document.getElementById("WROptions").value;
  
  WRRPFbtnn.insertAdjacentHTML("beforeend" , '- '+Status+' RPF as OTC ');
});

function WaiveRPF2() {
  let Status = document.getElementById("WROptions1").value;

  let WAIVENOTENote = "I can help "+Status+" the Reprocessing Charge as a one time courtesy as we understand life can happen unexpectedly, this does mean any other Reprocessing Charges that may be added in the future will require payment, is that ok?";

  document.getElementById("WRRPF").innerText = WAIVENOTENote;
  
}

const Pymttest = document.querySelector('#Pymttest');
Pymttest.addEventListener('click', () => {
  const Pymttestn = document.querySelector('#NoteOutput');

  let AmtAmt = document.getElementById("AmtNoteRPF").value;
  let Secret = document.getElementById("Last4").value;
  
  Pymttestn.insertAdjacentHTML("beforeend" , '- processed $'+AmtAmt+' on CC ending in '+Secret+' ');
});

function WaivePymt() {
  let Amt = document.getElementById("AmtNoteRPF").value;
  let Numbers = document.getElementById("Last4").value;
  
  let WaivePymtNote = "I'd be happy to waive the Reprocessing Charge as a one time courtesy after the remaining Past Due Balance is processed. Did you want to process the $"+Amt+" on the card ending in "+Numbers+"?";
  
  document.getElementById("PymtRequired").innerText = WaivePymtNote;
    
}

function buildServ() {

  var PName = document.getElementById('MEEPpet1').value;
  var PName2 = document.getElementById('MEEPpet2').value;
  var PName3 = document.getElementById("MEEPpet3").value;
  var PName4 = document.getElementById("MEEPpet4").value;
  var PName5 = document.getElementById("MEEPpet5").value;
  var PName6 = document.getElementById("MEEPpet6").value;

  var ServUsed = document.getElementById("Used").value;
  var WPBAL = document.getElementById("Plan").value;
  var InstallPaid = document.getElementById("Paid").value;
  var RPF = document.getElementById("RPF").value;
  var EndDate = document.getElementById("EndDate").value;
  var BK = document.getElementById("BK").value;

  var ServUsed2 = document.getElementById("Used2").value;
  var WPBAL2 = document.getElementById("Plan2").value;
  var InstallPaid2 = document.getElementById("Paid2").value;
  var RPF2 = document.getElementById("RPF2").value;
  var EndDate2 = document.getElementById("EndDate2").value;
  var BK2 = document.getElementById("BK2").value;

  var ServUsed3 = document.getElementById("Used3").value;
  var WPBAL3 = document.getElementById("Plan3").value;
  var InstallPaid3 = document.getElementById("Paid3").value;
  var RPF3 = document.getElementById("RPF3").value;
  var EndDate3 = document.getElementById("EndDate3").value;
  var BK3 = document.getElementById("BK3").value;

  var ServUsed4 = document.getElementById("Used4").value;
  var WPBAL4 = document.getElementById("Plan4").value;
  var InstallPaid4 = document.getElementById("Paid4").value;
  var RPF4 = document.getElementById("RPF4").value;
  var EndDate4 = document.getElementById("EndDate4").value;
  var BK4 = document.getElementById("BK4").value;

  var ServUsed5 = document.getElementById("Used5").value;
  var WPBAL5 = document.getElementById("Plan5").value;
  var InstallPaid5 = document.getElementById("Paid5").value;
  var RPF5 = document.getElementById("RPF5").value;
  var EndDate5 = document.getElementById("EndDate5").value;
  var BK5 = document.getElementById("BK5").value;

  var ServUsed6 = document.getElementById("Used6").value;
  var WPBAL6 = document.getElementById("Plan6").value;
  var InstallPaid6 = document.getElementById("Paid6").value;
  var RPF6 = document.getElementById("RPF6").value;
  var EndDate6 = document.getElementById("EndDate6").value;
  var BK6 = document.getElementById("BK6").value;

    let result = "Canceling a Wellness Plan is all based on usage. We figure in how much the hospitals have provided in services and how many payments you have made, and then we come to a final balance based on whichever costs less: the remaining balance of future Plan payments, or the remaining costs of service after deducting past payments. This means you will either pay for the services you have used, Or the remaining 12 month plan balance, whichever is the lesser of the two.";

    
    
    const codebreaker = document.createElement("br");
    
    document.getElementById("CMWC").innerHTML=result;
    document.getElementById("CMWC").style.background="whitesmoke";
    document.getElementById("CMWC").appendChild(codebreaker);
    
    
let PetNameBox = [];

let CxlBox = [];
let BKBox = [];
let FinalInstallBox = [];
let InstallAmtBox = [];

let Pnum = document.getElementById('petnum')
if (Pnum.value == "1"){
  var petloop = {NL:[
      {  Name: PName,
          Serv: ServUsed,
          WPBAL: WPBAL,
          AMT: InstallPaid,
          RPF: RPF,
          EndDate: EndDate,
          BK: BK}
    ]}
} else if (Pnum.value == "2"){
  var petloop = {NL:[
      {  Name: PName,
          Serv: ServUsed,
          WPBAL: WPBAL,
          AMT: InstallPaid,
          RPF: RPF,
          EndDate: EndDate,
          BK: BK},
      {  Name: PName2,
          Serv: ServUsed2,
          WPBAL: WPBAL2,
          AMT: InstallPaid2,
          RPF: RPF2,
          EndDate: EndDate2,
          BK: BK2}
  ]}
} else if (Pnum.value == "3"){
  var petloop = {NL:[
      {  Name: PName,
          Serv: ServUsed,
          WPBAL: WPBAL,
          AMT: InstallPaid,
          RPF: RPF,
          EndDate: EndDate,
          BK: BK},
      {  Name: PName2,
          Serv: ServUsed2,
          WPBAL: WPBAL2,
          AMT: InstallPaid2,
          RPF: RPF2,
          EndDate: EndDate2,
          BK: BK2},
      {  Name: PName3,
          Serv: ServUsed3,
          WPBAL: WPBAL3,
          AMT: InstallPaid3,
          RPF: RPF3,
          EndDate: EndDate3,
          BK: BK3}
  ]}
} else if (Pnum.value == "4"){
  var petloop = {NL:[
      {  Name: PName,
          Serv: ServUsed,
          WPBAL: WPBAL,
          AMT: InstallPaid,
          RPF: RPF,
          EndDate: EndDate,
          BK: BK},
      {  Name: PName2,
          Serv: ServUsed2,
          WPBAL: WPBAL2,
          AMT: InstallPaid2,
          RPF: RPF2,
          EndDate: EndDate2,
          BK: BK2},
      {  Name: PName3,
          Serv: ServUsed3,
          WPBAL: WPBAL3,
          AMT: InstallPaid3,
          RPF: RPF3,
          EndDate: EndDate3,
          BK: BK3},
      {  Name: PName4,
          Serv: ServUsed4,
          WPBAL: WPBAL4,
          AMT: InstallPaid4,
          RPF: RPF4,
          EndDate: EndDate4,
          BK: BK4}
  ]}
} else if (Pnum.value == "5"){
  var petloop = {NL:[
      {  Name: PName,
          Serv: ServUsed,
          WPBAL: WPBAL,
          AMT: InstallPaid,
          RPF: RPF,
          EndDate: EndDate,
          BK: BK},
      {  Name: PName2,
          Serv: ServUsed2,
          WPBAL: WPBAL2,
          AMT: InstallPaid2,
          RPF: RPF2,
          EndDate: EndDate2,
          BK: BK2},
      {  Name: PName3,
          Serv: ServUsed3,
          WPBAL: WPBAL3,
          AMT: InstallPaid3,
          RPF: RPF3,
          EndDate: EndDate3,
          BK: BK3},
      {  Name: PName4,
          Serv: ServUsed4,
          WPBAL: WPBAL4,
          AMT: InstallPaid4,
          RPF: RPF4,
          EndDate: EndDate4,
          BK: BK4},
      {  Name: PName5,
          Serv: ServUsed5,
          WPBAL: WPBAL5,
          AMT: InstallPaid5,
          RPF: RPF5,
          EndDate: EndDate5,
          BK: BK5}
  ]}
} else if (Pnum.value == "6"){
  var petloop = {NL:[
      {  Name: PName,
          Serv: ServUsed,
          WPBAL: WPBAL,
          AMT: InstallPaid,
          RPF: RPF,
          EndDate: EndDate,
          BK: BK},
      {  Name: PName2,
          Serv: ServUsed2,
          WPBAL: WPBAL2,
          AMT: InstallPaid2,
          RPF: RPF2,
          EndDate: EndDate2,
          BK: BK2},
      {  Name: PName3,
          Serv: ServUsed3,
          WPBAL: WPBAL3,
          AMT: InstallPaid3,
          RPF: RPF3,
          EndDate: EndDate3,
          BK: BK3},
      {  Name: PName4,
          Serv: ServUsed4,
          WPBAL: WPBAL4,
          AMT: InstallPaid4,
          RPF: RPF4,
          EndDate: EndDate4,
          BK: BK4},
      {  Name: PName5,
          Serv: ServUsed5,
          WPBAL: WPBAL5,
          AMT: InstallPaid5,
          RPF: RPF5,
          EndDate: EndDate5,
          BK: BK5},
      {  Name: PName6,
          Serv: ServUsed6,
          WPBAL: WPBAL6,
          AMT: InstallPaid6,
          RPF: RPF6,
          EndDate: EndDate6,
          BK: BK6}
  ]}
} 

let prof = petloop['NL'];
for(let i=0, len=prof.length; i<len; i++){
//    console.log(prof[i]);
  PetNameBox.push(prof[i].Name)
//    console.log(prof[i].Name);
console.log(prof[i].Name)
}

var filtername = PetNameBox.filter(function(x) {
return x !== "";
});

console.log(PetNameBox);
console.log(filtername);


let profile = petloop['NL'];
for(let i=0, len=profile.length; i<len; i++){
//    console.log(profile[i]);
    PetNameBox.push(profile[i].Name)
    CxlBox.push(profile[i].CxlCost)
    BKBox.push(profile[i].BK)
    FinalInstallBox.push(profile[i].today)
    InstallAmtBox.push(profile[i].x)
//    console.log(profile[i].Name);
}

let filteredlistloop = profile.filter((profile) => {
  return profile.Name != "";
})


console.log(filteredlistloop)
console.log(filteredlistloop[0].Name);
console.log(filteredlistloop[0].Serv);
console.log(filteredlistloop[0].WPBAL);
console.log(filteredlistloop[0].AMT);
console.log(filteredlistloop[0].RPF);


let MEEPcmwc = filteredlistloop;
for(let i=0, len=MEEPcmwc.length; i<len; i++){
  var PName = (MEEPcmwc[i].Name);
  var ServUsed = (MEEPcmwc[i].Serv);
  var WPBAL = (MEEPcmwc[i].WPBAL);
  var InstallPaid = (MEEPcmwc[i].AMT);
  var RPF = (MEEPcmwc[i].RPF);
  var EndDate = (MEEPcmwc[i].EndDate);

  if ( (parseInt(ServUsed) > parseInt(WPBAL) && parseInt(WPBAL) <= parseInt(InstallPaid)) ){
      var P = "Looking at "+PName+"'s plan, as all 12 installments have been paid we can close their plan today at no cost";
      var note = "- adv $0 per WP BAL for "+PName+" - Cxled "+PName+" at no cost ";
      
      } else if ( parseInt(ServUsed) > parseInt(WPBAL) ) {
      
        var RPFc=(RPF*20);  // Total cost of all RPF's
        var w=(WPBAL - RPFc); //cost of plan without RPF's
        var x=(w/12).toFixed(2);     //cost of each installment
        var CxlCost=(WPBAL-InstallPaid).toFixed(2); //cxlcost for services cxl
        var q=Math.round(CxlCost/x); //number of remaining installments on wellness plan 
        
        var P = "Looking at "+PName+"'s plan, as $"+ServUsed+" of services were used and the plan costs $"+WPBAL+", we can close for the lesser of the two amounts being the cost of the plan. We then subtract the $"+InstallPaid+" of installments paid, which leaves the cost to close today of $"+CxlCost+". This can either be paid today or over the remaining "+q+" installments of $"+x+" each month before the plan expires on "+EndDate+".";
        
        var note = "-adv $"+CxlCost+" or "+q+" installments of "+x+" per WP BAL for "+PName+" ";
      
      } else if ( (parseInt(ServUsed) < parseInt(WPBAL) && parseInt(ServUsed) <= parseInt(InstallPaid)) ){
      var P = "Looking at "+PName+"'s plan, as all services used have been paid for with the monthly installments we can close the plan today at no cost.";
      var note = "-adv $0 per Services for "+PName+" - cxled at $0 ";
      
      } else if ( parseInt(ServUsed) < parseInt(WPBAL) ) {
        var RPFc=(RPF*20);  // Total cost of all RPF's
        var w=(WPBAL - RPFc); //cost of plan without RPF's
        var x=(w/12).toFixed(2);     //cost of each installment
        var CxlCost=(ServUsed-InstallPaid).toFixed(2); //cxlcost for services cxl
        var q=Math.round(CxlCost/x); //number of remaining installments on wellness plan 
        let y=Math.trunc(CxlCost/x);  //Number of installments to call after = services cxl
        let z=Math.abs([x*y]-CxlCost).toFixed(2); //remaining balance to pay when they call back after - services cxl
      
        let BK = document.getElementById("BK").value;
            var today = new Date();{
            var dd = today.getDate();
            var mm = today.getMonth();
            var yyyy = today.getFullYear();
            
            if(parseInt(BK) < dd)
            {
                var mm= ((mm+2) + y);
            } else {
            
               var mm = ((mm+1) + y);
            }
                
                if(mm>12) 
                {
                    mm=mm-12;
                } 
                
                today = mm+'/'+BK+'/'+yyyy;
                console.log(today);
                console.log(y);
                console.log(mm);
                }
        
          var P = "Looking at "+PName+"'s plan, as $"+ServUsed+" of services were used and the plan costs $"+WPBAL+", we can close for the lesser of the two amounts being the cost of the services used. We then subtract the $"+InstallPaid+" of installments paid, which leaves the cost to close today of $"+CxlCost+". This can either be paid today or we can let each monthly installment of $"+x+" lower the balance each month over time, I do recommend calling back before the installment on "+today+" to pay the remaining $"+z+". Please keep in mind if you do not reach out the plan will fulfill the year and end automatically on "+EndDate+" and You will also want to avoid using anymore services as closing the plan is based on usage; using more services will adjust the cost to cancel accordingly.";
        
          var note = "-adv $"+CxlCost+" per Services for "+PName+" adv to cb before " +today+ " to pay the remaining $"+z+" to avoid overpymt ";
      }

      MEEPcmwc[i].CxlCost=CxlCost;
      MEEPcmwc[i].InstAmt=x;
      MEEPcmwc[i].P=P;
      MEEPcmwc[i].note=note;

      
      const node = document.createTextNode(MEEPcmwc[i].P);

      const codebreaker = document.createElement("br");

      node.appendChild

      const MEEPonen = document.querySelector('#CMWC');
      MEEPonen.insertAdjacentHTML("beforeend" , ' <br>');
            

      document.getElementById("CMWC").appendChild(node);
      document.getElementById("CMWC").appendChild(codebreaker);
      document.getElementById("CMWC").appendChild(codebreaker);
      document.getElementById("CMWC").appendChild(codebreaker);
      };

console.log(MEEPcmwc)

let scribe = profile.filter((profile) => {
  return profile.CxlCost > '0'
})
console.log(scribe)


if (scribe.length == 6) {
  var Ending = "The $"+scribe[0].CxlCost+" for "+scribe[0].Name+", $"+scribe[1].CxlCost+" for "+scribe[1].Name+", $"+scribe[2].CxlCost+ " for "+scribe[2].Name+", The $"+scribe[3].CxlCost+" for "+scribe[3].Name+", The $"+scribe[4].CxlCost+" for "+scribe[4].Name+", and The $"+scribe[5].CxlCost+" for "+scribe[5].Name+", can either be paid today or over the remaining installments. Which option do you prefer?";

} else if (scribe.length == 5) {
  var Ending = "The $"+scribe[0].CxlCost+" for "+scribe[0].Name+", $"+scribe[1].CxlCost+" for "+scribe[1].Name+", $"+scribe[2].CxlCost+ " for "+scribe[2].Name+", The $"+scribe[3].CxlCost+" for "+scribe[3].Name+", and The $"+scribe[4].CxlCost+" for "+scribe[4].Name+" can either be paid today or over the remaining installments. Which option do you prefer?";

} else if (scribe.length == 4) {
  var Ending = "The $"+scribe[0].CxlCost+" for "+scribe[0].Name+", $"+scribe[1].CxlCost+" for "+scribe[1].Name+", $"+scribe[2].CxlCost+ " for "+scribe[2].Name+", and The $"+scribe[3].CxlCost+" for "+scribe[3].Name+" can either be paid today or over the remaining installments. Which option do you prefer?";

} else if (scribe.length == 3) {
  var Ending = "The $"+scribe[0].CxlCost+" for "+scribe[0].Name+", $"+scribe[1].CxlCost+" for "+scribe[1].Name+", and the $"+scribe[2].CxlCost+ " for "+scribe[2].Name+" can either be paid today or over the remaining installments. Which option do you prefer?";

} else if (scribe.length == 2) {
  var Ending = "The $"+scribe[0].CxlCost+" for "+scribe[0].Name+" and $"+scribe[1].CxlCost+" for "+scribe[1].Name+" can either be paid today or over the remaining installments. Which option do you prefer?";

} else if (scribe.length == 1) {
  var Ending = "The $"+scribe[0].CxlCost+" for "+scribe[0].Name+" can either be paid today or over the remaining installments. Which option do you prefer?";

} else {
  var Ending = "";
}

if (MEEPcmwc.length == 6) {
  var EndNote = ""+MEEPcmwc[0].note+""+MEEPcmwc[1].note+""+MEEPcmwc[2].note+""+MEEPcmwc[3].note+""+MEEPcmwc[4].note+""+MEEPcmwc[5].note+"";

  var P = ""+MEEPcmwc[0].P+"<br><br>"+MEEPcmwc[1].P+"<br><br>"+MEEPcmwc[2].P+"<br><br>"+MEEPcmwc[3].P+"<br><br>"+MEEPcmwc[4].P+"<br><br>"+MEEPcmwc[5].P+"";

} else if (MEEPcmwc.length == 5) {
  var EndNote = ""+MEEPcmwc[0].note+""+MEEPcmwc[1].note+""+MEEPcmwc[2].note+""+MEEPcmwc[3].note+""+MEEPcmwc[4].note+"";

  var P = ""+MEEPcmwc[0].P+"<br><br>"+MEEPcmwc[1].P+"<br><br>"+MEEPcmwc[2].P+"<br><br>"+MEEPcmwc[3].P+"<br><br>"+MEEPcmwc[4].P+"";

} else if (MEEPcmwc.length == 4) {
  var EndNote = ""+MEEPcmwc[0].note+""+MEEPcmwc[1].note+""+MEEPcmwc[2].note+""+MEEPcmwc[3].note+"";

  var P = ""+MEEPcmwc[0].P+"<br><br>"+MEEPcmwc[1].P+"<br><br>"+MEEPcmwc[2].P+"<br><br>"+MEEPcmwc[3].P+"";

} else if (MEEPcmwc.length == 3) {
  var EndNote = ""+MEEPcmwc[0].note+""+MEEPcmwc[1].note+""+MEEPcmwc[2].note+"";

  var P = ""+MEEPcmwc[0].P+"<br><br>"+MEEPcmwc[1].P+"<br><br>"+MEEPcmwc[2].P+"";

} else if (MEEPcmwc.length == 2) {
  var EndNote = ""+MEEPcmwc[0].note+""+MEEPcmwc[1].note+"";

  var P = "<br>"+MEEPcmwc[0].P+"<br>"+MEEPcmwc[1].P+"<br>";

} else if (MEEPcmwc.length == 1) {
  var EndNote = ""+MEEPcmwc[0].note+"";

  var P = ""+MEEPcmwc[0].P+"";

} else {
  var EndNote = "";

  var P = "";
}


document.getElementById("Ending").innerHTML = Ending;

const MEEPone = document.querySelector('#MEEPbtn1');
MEEPone.addEventListener('click', () => {
  const MEEPonen = document.querySelector('#NoteOutput');
  MEEPonen.insertAdjacentHTML("beforeend" , EndNote);
});
 

};

function RemovingMedsSubmit() {
  let BalOwed = document.getElementById('BODDRMQR').value;
  
  if (BalOwed == 'Yes'){

    let Name = document.getElementById('RMNames').value;
    let Med = document.getElementById('MedList').value;
    let NMR = document.getElementById('NMRRMQR').value;
    let AmtOwed = document.getElementById('AMTOWEDRM').value;

    let RMNotes = "When we add medication to a wellness plan the total cost of the medication is applied over the remaining installments left in the plan year. To remove the medication we can pay for the medication that has already been provided but hasn't been paid yet with the monthly installments. For "+Name+", I'm showing there is a balance of $"+AmtOwed+" to remove the "+Med+" from the plan, this will reduce the remaining monthly installments to $"+NMR+" moving forward without the medication.";
    
  
    document.getElementById('RMNC').innerText= RMNotes;
  } else if (BalOwed == 'No') {

    let Name = document.getElementById('RMNames').value;
    let Med = document.getElementById('MedList').value;
    let NMR = document.getElementById('NMRRMQR').value;

    let RMNotes = "I'm showing I can remove the "+Med+" from "+Name+"'s plan today at no cost, this will make the remaining installments $"+NMR+" moving forward without the medication.";

    document.getElementById('RMNC').innerText= RMNotes;
  }

}

document.getElementById("RMsubmitbtn").addEventListener("click", unhideMedRemov);

function unhideMedRemov() {
  // get the clock
  var Remov = document.getElementById('HideMedBlock');

  // get the current value of the clock's display property
  var RemovSetting = Remov.style.display;

  // also get the clock button, so we can change what it says

  // now toggle the clock and the button text, depending on current state
  if (RemovSetting == 'none') {
    // clock is visible. hide it
    Remov.style.display = 'block';
    // change button text

  }
  else {

  }
}
