package handlers

import (
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin/render"
)

// HTMLRenderer, her sayfa için ayrı template setlerini yönetir.
type HTMLRenderer struct {
	Templates map[string]*template.Template
}

// Instance, render işlemini gerçekleştirir.
func (r *HTMLRenderer) Instance(name string, data interface{}) render.Render {
	return render.HTML{
		Template: r.Templates[name],
		Data:     data,
	}
}

// Render, HTTP yanıtını yazar.
func (r *HTMLRenderer) Render(w http.ResponseWriter, code int, data ...interface{}) error {
	name := data[0].(string)
	templateData := data[1]
	instance := r.Instance(name, templateData)
	return instance.Render(w)
} 