from src import Parser, Detection, Pipeline, Analyzer, Report

def main():
    log_file_path = "/home/natty/python-projects/myproject/log-analyzers/logs/auth_sample.log"
    json_file_path = "/home/natty/python-projects/myproject/log-analyzers/output/log_analysis_report.json"
    parser_object = Parser()
    result_list = parser_object.parsing(log_file_path)
    pipe_object = Pipeline(log_file_path, json_file_path)
    analyzer_object = Analyzer(json_file_path)
    report_object = Report(json_file_path)
    report_object.report()
  

if __name__ == "__main__":
    main()

