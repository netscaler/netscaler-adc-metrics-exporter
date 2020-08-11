# Changelog
All notable changes to this project will be documented in this file.


## [1.4.4] - 2020-06-15
### Added
 - SSLvserver metrics
 - New Label "citrixadc_server_name" for configured servicegroups under "services" stats.
 - Bug Fix for serial ADC connection 
 - Added package "iputils" in container image for debugging at runtime
 
## [1.4.5] - 2020-08-11
### Added
 - Python update : 2.7 to 3.8
 - New Label: "citrixadc_interface_id" for Interface metrics
 - Default LogLevel : INFO

### BugFixes:
 - Connection retries for ADC only on new Prometheus Requests.
 - Single Login Session.
