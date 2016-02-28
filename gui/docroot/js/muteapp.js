var muteApp = angular.module('muteApp', []);

muteApp.controller('muteListsCtrl', ['$scope', '$http',
  function ($scope, $http) {
  	$scope.pseudonyms=[];
    $scope.limit=20;
    $scope.page=0
    $scope.folder="inbox";
    $scope.pseydonym=null;
    $scope.display_message=false;
    $scope.edit_message=false;
    $scope.show_settings=false;
    $scope.actMessage={};
    $scope.newMessage={};
    $scope.settingsContent={};

    $scope.getPseudonyms = function getPseudonyms(promise){
      $http.get('/api/pseudonyms.json').success(function(data) {
        $scope.pseudonyms = data;
        if ( $scope.pseudonym === undefined || $scope.pseudonym === null){
          $scope.pseudonym=$scope.pseudonyms[0];
        }
        $scope.refresh()
        if (promise !== null){
          promise();
        }
      });
    }

    $scope.updateContactList=function updateContactList(){
      if ( $scope.pseudonym !== undefined && $scope.pseudonym !== null
          && $scope.pseudonym.name !== undefined && $scope.pseudonym.name !== null ){
        $http.get('/api/'+$scope.pseudonym.name+'/contacts.json').success(function(data){
          $scope.contacts=data;
        });
      }
    }

    $scope.updateMessageList=function updateMessageList(page){
      $scope.display_message=false;
      $scope.edit_message=false;
      if ( page === undefined || page === null || page < 0 ){
        page=0;
      }

      $scope.page=page
        if ( $scope.pseudonym !== undefined && $scope.pseudonym !== null
          && $scope.pseudonym.name !== undefined && $scope.pseudonym.name !== null ){
          $http.get('/api/'+$scope.pseudonym.name+'/messages/'+$scope.folder+'.json?limit='+$scope.limit+'&page='+$scope.page).success(function(data){
           $scope.messages=data;
          });
        }
    }

    $scope.refresh = function refresh(){
      $scope.updateContactList();
      $scope.updateMessageList();
      $scope.hideMessage();
    }

    $scope.fetch=function fetch(){
      if ( $scope.pseudonym !== undefined && $scope.pseudonym !== null
          && $scope.pseudonym.name !== undefined && $scope.pseudonym.name !== null ){
          $http.get('/api/'+$scope.pseudonym.name+'/get/').success(function(data){
            if (data.new == true) {
              $scope.folder="inbox";
              $scope.refresh();
            }
          });
      }
    }

    $scope.hideMessage=function hideMessage(){
      $scope.display_message=false;
      $scope.edit_message=false;
      $scope.show_settings=false;
      $scope.actMessage={};
      $scope.newMessage={};
    }

    $scope.showMessage=function showMessage(msgid){
      $scope.hideMessage();
      $http.get('/api/'+$scope.pseudonym.name+'/message/'+msgid).success(function(data){
          $scope.actMessage=data;
          $scope.display_message=true;
        });
    }

    $scope.composeMessage=function composeMessage(to,msgid){
      $scope.hideMessage();
      if (msgid === undefined || msgid == null){
        $scope.newMessage.To=to
        $scope.edit_message=true;
      }else{
        $http.get('/api/'+$scope.pseudonym.name+'/message/'+msgid).success(function(data){
          $scope.newMessage=data;
          $scope.newMessage={
            "To":data.From,
            "Subject":"Re: "+data.Subject,
            "CC":data.CC,
            "InReplyTo":data.messageid,
            "Body":data.Body
          }
          $scope.edit_message=true;
        });
      }
    }

    $scope.deleteMessage=function deleteMessage(msgid){
      $http.post('/api/'+$scope.pseudonym.name+'/delete/'+msgid,{"MessageID":msgid}).success(function(data){
        $scope.hideMessage();
        $scope.refresh();
      });
    }

    $scope.send=function send(){
      $scope.newMessage.Pseudonym=$scope.pseudonym.name;
      if ($scope.edit_message == true) {
        $http.post('/api/'+$scope.pseudonym.name+'/send', $scope.newMessage).success(function(data){
          if (data.status=="ok"){
            alert("Sent!");
            $scope.hideMessage();
          }else{
            alert("Error")
          }
        });
      }
    }

    $scope.showSettings=function showSettings(){
      $http.get('/api/settings').success(function(data){
        $scope.settingsContent=data;
        $scope.show_settings=true;
      });
    }

    $scope.saveSettings=function saveSettings(){
      $http.post('/api/settings',$scope.settingsContent).success(function(data){
        $scope.hideMessage();
      });
    }

    $scope.getPseudonyms($scope.refresh);

  }]);
