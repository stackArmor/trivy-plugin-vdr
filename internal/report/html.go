package report

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"io"
	"os"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

//go:embed templates/default.html
var templateFS embed.FS

type htmlTemplateData struct {
	Report     model.Report
	ReportJSON template.JS
}

func RenderHTML(w io.Writer, report model.Report, templatePath string) error {
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return err
	}
	templateBody, err := htmlTemplateBody(templatePath)
	if err != nil {
		return err
	}
	tmpl, err := template.New("vdr-html").Parse(string(templateBody))
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, htmlTemplateData{Report: report, ReportJSON: template.JS(reportJSON)}); err != nil {
		return err
	}
	_, err = w.Write(buf.Bytes())
	return err
}

func htmlTemplateBody(templatePath string) ([]byte, error) {
	if templatePath != "" {
		return os.ReadFile(templatePath)
	}
	return templateFS.ReadFile("templates/default.html")
}
