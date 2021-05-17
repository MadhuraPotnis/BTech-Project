package com.example.ids.db;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "traffic_samples_store", schema = "ids")
public class TrafficSamplesStore {

	@Id
	@Column(name = "sample_id")
	public Long sampleId;

	@Column(name = "ip_proto")
	public float ipProto;
	
	@Column(name = "ip_len_mean")
	public float ipLenMean;
	
	@Column(name = "ip_len_median")
	public float ipLenMedian;
	
	@Column(name = "ip_len_var")
	public float ipLenVar;
	
	@Column(name = "ip_len_entropy")
	public float ipLenEntropy;
	
	@Column(name = "ip_len_cv")
	public float ipLenCv;
	
	@Column(name = "ip_len_cvq")
	public float ipLenCvq;
	
	@Column(name = "ip_len_rte")
	public float ipLenRte;
	
	@Column(name = "ip_ttl_mean")
	public float ipTtlMean;
	
	@Column(name = "ip_ttl_median")
	public float ipTtlMedian;
	
	@Column(name = "ip_ttl_var")
	public float ipTtlVar;
	
	@Column(name = "ip_ttl_std")
	public float ipTtlStd;
	
	@Column(name = "ip_ttl_entropy")
	public float ipTtlEntropy;
	
	@Column(name = "ip_ttl_cv")
	public float ipTtlCv;
	
	@Column(name = "ip_ttl_cvq")
	public float ipTtlCvq;
	
	@Column(name = "ip_ttl_rte")
	public float ipTtlRte;
	
	@Column(name = "sport_var")
	public float sportVar;
	
	@Column(name = "sport_cv")
	public float sportCv;
	
	@Column(name = "sport_median")
	public float sportMedian;
	
	@Column(name = "sport_std")
	public float sportStd;

	@Column(name = "sport_entropy")
	public float sportEntropy;

	@Column(name = "sport_cvq")
	public float sportCvq;

	@Column(name = "sport_rte")
	public float sportRte;

	@Column(name = "dport_mean")
	public float dportMean;

	@Column(name = "dport_median")
	public float dportMedian;

	@Column(name = "dport_var")
	public float dportVar;

	@Column(name = "dport_cvq")
	public float dportCvq;

	@Column(name = "tcp_seq_mean")
	public float tcpSeqMean;

	@Column(name = "tcp_seq_median")
	public float tcpSeqMedian;

	@Column(name = "tcp_seq_std")
	public float tcpSeqStd;

	@Column(name = "tcp_seq_entropy")
	public float tcpSeqEntropy;

	@Column(name = "tcp_seq_cv")
	public float tcpSeqCv;

	@Column(name = "tcp_seq_cvq")
	public float tcpSeqCvq;

	@Column(name = "tcp_seq_rte")
	public float tcpSeqRte;

	@Column(name = "tcp_ack_median")
	public float tcpAckMedian;

	@Column(name = "tcp_ack_var")
	public float tcpAckVar;

	@Column(name = "tcp_ack_std")
	public float tcpAckStd;

	@Column(name = "tcp_ack_cv")
	public float tcpAckCv;

	@Column(name = "tcp_ack_cvq")
	public float tcpAckCvq;

	@Column(name = "tcp_dataofs_var")
	public float tcpDataofsVar;

	@Column(name = "tcp_dataofs_entropy")
	public float tcpDataofsEntropy;

	@Column(name = "tcp_dataofs_cvq")
	public float tcpDataofsCvq;

	@Column(name = "tcp_dataofs_rte")
	public float tcpDataofsRte;

	@Column(name = "tcp_flags_median")
	public float tcpFlagsMedian;

	@Column(name = "tcp_flags_entropy")
	public float tcpFlagsEntropy;

	@Column(name = "tcp_flags_cvq")
	public float tcpFlagsCvq;

	@Column(name = "tcp_flags_rte")
	public float tcpFlagsRte;

	@Column(name = "tcp_window_mean")
	public float tcpWindowMean;

	@Column(name = "tcp_window_var")
	public float tcpWindowVar;

	@Column(name = "tcp_window_std")
	public float tcpWindowStd;

	@Column(name = "tcp_window_entropy")
	public float tcpWindowEntropy;

	@Column(name = "tcp_window_cvq")
	public float tcpWindowCvq;

	@Column(name = "tcp_window_median")
	public float tcpWindowMedian;

	@Column(name = "tcp_window_rte")
	public float tcpWindowRte;
							
	@Column(name = "sample_label")
	public Long sampleLabel;

	public Long getSampleId() {
		return sampleId;
	}

	public void setSampleId(Long sampleId) {
		this.sampleId = sampleId;
	}

	public float getIpProto() {
		return ipProto;
	}

	public void setIpProto(float ipProto) {
		this.ipProto = ipProto;
	}

	public float getIpLenMean() {
		return ipLenMean;
	}

	public void setIpLenMean(float ipLenMean) {
		this.ipLenMean = ipLenMean;
	}

	public float getIpLenMedian() {
		return ipLenMedian;
	}

	public void setIpLenMedian(float ipLenMedian) {
		this.ipLenMedian = ipLenMedian;
	}

	public float getIpLenVar() {
		return ipLenVar;
	}

	public void setIpLenVar(float ipLenVar) {
		this.ipLenVar = ipLenVar;
	}

	public float getIpLenEntropy() {
		return ipLenEntropy;
	}

	public void setIpLenEntropy(float ipLenEntropy) {
		this.ipLenEntropy = ipLenEntropy;
	}

	public float getIpLenCv() {
		return ipLenCv;
	}

	public void setIpLenCv(float ipLenCv) {
		this.ipLenCv = ipLenCv;
	}

	public float getIpLenCvq() {
		return ipLenCvq;
	}

	public void setIpLenCvq(float ipLenCvq) {
		this.ipLenCvq = ipLenCvq;
	}

	public float getIpLenRte() {
		return ipLenRte;
	}

	public void setIpLenRte(float ipLenRte) {
		this.ipLenRte = ipLenRte;
	}

	public float getIpTtlMean() {
		return ipTtlMean;
	}

	public void setIpTtlMean(float ipTtlMean) {
		this.ipTtlMean = ipTtlMean;
	}

	public float getIpTtlMedian() {
		return ipTtlMedian;
	}

	public void setIpTtlMedian(float ipTtlMedian) {
		this.ipTtlMedian = ipTtlMedian;
	}

	public float getIpTtlVar() {
		return ipTtlVar;
	}

	public void setIpTtlVar(float ipTtlVar) {
		this.ipTtlVar = ipTtlVar;
	}

	public float getIpTtlStd() {
		return ipTtlStd;
	}

	public void setIpTtlStd(float ipTtlStd) {
		this.ipTtlStd = ipTtlStd;
	}

	public float getIpTtlEntropy() {
		return ipTtlEntropy;
	}

	public void setIpTtlEntropy(float ipTtlEntropy) {
		this.ipTtlEntropy = ipTtlEntropy;
	}

	public float getIpTtlCv() {
		return ipTtlCv;
	}

	public void setIpTtlCv(float ipTtlCv) {
		this.ipTtlCv = ipTtlCv;
	}

	public float getIpTtlCvq() {
		return ipTtlCvq;
	}

	public void setIpTtlCvq(float ipTtlCvq) {
		this.ipTtlCvq = ipTtlCvq;
	}

	public float getIpTtlRte() {
		return ipTtlRte;
	}

	public void setIpTtlRte(float ipTtlRte) {
		this.ipTtlRte = ipTtlRte;
	}

	public float getSportVar() {
		return sportVar;
	}

	public void setSportVar(float sportVar) {
		this.sportVar = sportVar;
	}

	public float getSportCv() {
		return sportCv;
	}

	public void setSportCv(float sportCv) {
		this.sportCv = sportCv;
	}

	public float getSportMedian() {
		return sportMedian;
	}

	public void setSportMedian(float sportMedian) {
		this.sportMedian = sportMedian;
	}

	public float getSportStd() {
		return sportStd;
	}

	public void setSportStd(float sportStd) {
		this.sportStd = sportStd;
	}

	public float getSportEntropy() {
		return sportEntropy;
	}

	public void setSportEntropy(float sportEntropy) {
		this.sportEntropy = sportEntropy;
	}

	public float getSportCvq() {
		return sportCvq;
	}

	public void setSportCvq(float sportCvq) {
		this.sportCvq = sportCvq;
	}

	public float getSportRte() {
		return sportRte;
	}

	public void setSportRte(float sportRte) {
		this.sportRte = sportRte;
	}

	public float getDportMean() {
		return dportMean;
	}

	public void setDportMean(float dportMean) {
		this.dportMean = dportMean;
	}

	public float getDportMedian() {
		return dportMedian;
	}

	public void setDportMedian(float dportMedian) {
		this.dportMedian = dportMedian;
	}

	public float getDportVar() {
		return dportVar;
	}

	public void setDportVar(float dportVar) {
		this.dportVar = dportVar;
	}

	public float getDportCvq() {
		return dportCvq;
	}

	public void setDportCvq(float dportCvq) {
		this.dportCvq = dportCvq;
	}

	public float getTcpSeqMean() {
		return tcpSeqMean;
	}

	public void setTcpSeqMean(float tcpSeqMean) {
		this.tcpSeqMean = tcpSeqMean;
	}

	public float getTcpSeqMedian() {
		return tcpSeqMedian;
	}

	public void setTcpSeqMedian(float tcpSeqMedian) {
		this.tcpSeqMedian = tcpSeqMedian;
	}

	public float getTcpSeqStd() {
		return tcpSeqStd;
	}

	public void setTcpSeqStd(float tcpSeqStd) {
		this.tcpSeqStd = tcpSeqStd;
	}

	public float getTcpSeqEntropy() {
		return tcpSeqEntropy;
	}

	public void setTcpSeqEntropy(float tcpSeqEntropy) {
		this.tcpSeqEntropy = tcpSeqEntropy;
	}

	public float getTcpSeqCv() {
		return tcpSeqCv;
	}

	public void setTcpSeqCv(float tcpSeqCv) {
		this.tcpSeqCv = tcpSeqCv;
	}

	public float getTcpSeqCvq() {
		return tcpSeqCvq;
	}

	public void setTcpSeqCvq(float tcpSeqCvq) {
		this.tcpSeqCvq = tcpSeqCvq;
	}

	public float getTcpSeqRte() {
		return tcpSeqRte;
	}

	public void setTcpSeqRte(float tcpSeqRte) {
		this.tcpSeqRte = tcpSeqRte;
	}

	public float getTcpAckMedian() {
		return tcpAckMedian;
	}

	public void setTcpAckMedian(float tcpAckMedian) {
		this.tcpAckMedian = tcpAckMedian;
	}

	public float getTcpAckVar() {
		return tcpAckVar;
	}

	public void setTcpAckVar(float tcpAckVar) {
		this.tcpAckVar = tcpAckVar;
	}

	public float getTcpAckStd() {
		return tcpAckStd;
	}

	public void setTcpAckStd(float tcpAckStd) {
		this.tcpAckStd = tcpAckStd;
	}

	public float getTcpAckCv() {
		return tcpAckCv;
	}

	public void setTcpAckCv(float tcpAckCv) {
		this.tcpAckCv = tcpAckCv;
	}

	public float getTcpAckCvq() {
		return tcpAckCvq;
	}

	public void setTcpAckCvq(float tcpAckCvq) {
		this.tcpAckCvq = tcpAckCvq;
	}

	public float getTcpDataofsVar() {
		return tcpDataofsVar;
	}

	public void setTcpDataofsVar(float tcpDataofsVar) {
		this.tcpDataofsVar = tcpDataofsVar;
	}

	public float getTcpDataofsEntropy() {
		return tcpDataofsEntropy;
	}

	public void setTcpDataofsEntropy(float tcpDataofsEntropy) {
		this.tcpDataofsEntropy = tcpDataofsEntropy;
	}

	public float getTcpDataofsCvq() {
		return tcpDataofsCvq;
	}

	public void setTcpDataofsCvq(float tcpDataofsCvq) {
		this.tcpDataofsCvq = tcpDataofsCvq;
	}

	public float getTcpDataofsRte() {
		return tcpDataofsRte;
	}

	public void setTcpDataofsRte(float tcpDataofsRte) {
		this.tcpDataofsRte = tcpDataofsRte;
	}

	public float getTcpFlagsMedian() {
		return tcpFlagsMedian;
	}

	public void setTcpFlagsMedian(float tcpFlagsMedian) {
		this.tcpFlagsMedian = tcpFlagsMedian;
	}

	public float getTcpFlagsEntropy() {
		return tcpFlagsEntropy;
	}

	public void setTcpFlagsEntropy(float tcpFlagsEntropy) {
		this.tcpFlagsEntropy = tcpFlagsEntropy;
	}

	public float getTcpFlagsCvq() {
		return tcpFlagsCvq;
	}

	public void setTcpFlagsCvq(float tcpFlagsCvq) {
		this.tcpFlagsCvq = tcpFlagsCvq;
	}

	public float getTcpFlagsRte() {
		return tcpFlagsRte;
	}

	public void setTcpFlagsRte(float tcpFlagsRte) {
		this.tcpFlagsRte = tcpFlagsRte;
	}

	public float getTcpWindowMean() {
		return tcpWindowMean;
	}

	public void setTcpWindowMean(float tcpWindowMean) {
		this.tcpWindowMean = tcpWindowMean;
	}

	public float getTcpWindowVar() {
		return tcpWindowVar;
	}

	public void setTcpWindowVar(float tcpWindowVar) {
		this.tcpWindowVar = tcpWindowVar;
	}

	public float getTcpWindowStd() {
		return tcpWindowStd;
	}

	public void setTcpWindowStd(float tcpWindowStd) {
		this.tcpWindowStd = tcpWindowStd;
	}

	public float getTcpWindowEntropy() {
		return tcpWindowEntropy;
	}

	public void setTcpWindowEntropy(float tcpWindowEntropy) {
		this.tcpWindowEntropy = tcpWindowEntropy;
	}

	public float getTcpWindowCvq() {
		return tcpWindowCvq;
	}

	public void setTcpWindowCvq(float tcpWindowCvq) {
		this.tcpWindowCvq = tcpWindowCvq;
	}

	public float getTcpWindowMedian() {
		return tcpWindowMedian;
	}

	public void setTcpWindowMedian(float tcpWindowMedian) {
		this.tcpWindowMedian = tcpWindowMedian;
	}

	public float getTcpWindowRte() {
		return tcpWindowRte;
	}

	public void setTcpWindowRte(float tcpWindowRte) {
		this.tcpWindowRte = tcpWindowRte;
	}

	public Long getSampleLabel() {
		return sampleLabel;
	}

	public void setSampleLabel(Long sampleLabel) {
		this.sampleLabel = sampleLabel;
	}
	
}
