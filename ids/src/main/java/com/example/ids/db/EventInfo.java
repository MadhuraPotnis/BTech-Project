package com.example.ids.db;

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "event_info", schema = "ids")
public class EventInfo {

	@Id
	@Column(name = "event_id")
	public Long eventId;

	@Column(name = "detection_time")
	public Date detectionTime;
	
	@Column(name = "event_name")
	public String eventName;

	@Column(name = "description")
	public String description;
	
	@Column(name = "source_ip")
	public String sourceIp;

	@Column(name = "source_port")
	public Long sourcePort;
	
	@Column(name = "dest_ip")
	public String destIp;

	@Column(name = "dest_port")
	public Long destPort;
	
	@Column(name = "classification_flag")
	public Long classificationFlag;
}
