package identity

import "testing"

func TestStageRotationRejectsInvalidCertificate(t *testing.T){pending,err:=Generate("test-agent","agent.test.invalid");if err!=nil{t.Fatal(err)};_,err=StageRotation(t.TempDir(),pending,RotationResponse{CertificateID:"test-only",CertificatePEM:"not a certificate"});if err==nil{t.Fatal("invalid rotation certificate was accepted")}}

func TestActivateRotationRejectsExternalStage(t *testing.T){if err:=ActivateRotation(t.TempDir(),t.TempDir());err==nil{t.Fatal("external staging directory was accepted")}}
